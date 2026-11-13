package scheduler

import (
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/sdk/kplugin"
)

// svcIPName is the IP the silo's service has its address from ("" if none).
func svcIPName(s *v1.Silo) string {
	n, _ := v1.SiloServiceIP(s)
	return n
}

func findIP(env Env, ns, name string) *v1.IP {
	for _, x := range env.IPs {
		if x.Namespace == ns && x.Name == name {
			return x
		}
	}
	return nil
}

// heldIP is the IP named name if the silo holds it (nil otherwise: not made, not bound yet, or
// someone else's).
func heldIP(s *v1.Silo, name string, env Env) *v1.IP {
	if name == "" {
		return nil
	}
	if x := findIP(env, s.Namespace, name); x != nil && x.Status.BoundUID == s.UID && s.UID != "" {
		return x
	}
	return nil
}

// ipFilter: the rules a host must meet for the silo's IPs (empty: fine). The silo must hold each
// IP first; an ip-pool address only goes on the host it's routed to (or, not reserved yet, a host
// with one free); a plugin's address only where its class lets it follow (its region, by default).
func ipFilter(s *v1.Silo, h *v1.Host, env Env) string {
	for _, name := range v1.SiloIPs(s) {
		x := findIP(env, s.Namespace, name)
		switch {
		case x == nil:
			if n, made := v1.SiloServiceIP(s); made && n == name {
				return "waiting for IP " + name + " to be made for it"
			}
			return "IP " + name + " doesn't exist"
		case x.Status.BoundUID != s.UID || s.UID == "":
			if x.Status.BoundTo != "" && x.Status.BoundTo != v1.HolderSiloPrefix+s.Name {
				return "IP " + name + " is held by " + x.Status.BoundTo
			}
			if n, made := v1.SiloServiceIP(s); made && n == name && !ownedBy(x, s.UID) {
				return "IP " + name + " exists and wasn't made for it: name it in loadBalancer.ip to take it"
			}
			return "waiting for IP " + name + " to be bound to it"
		}
		if x.Spec.Class == v1.LBIPPool {
			where := x.Status.Host
			if where == "" {
				where = x.Spec.Host
			}
			if where != "" && where != h.Name {
				return "IP " + name + "'s address is routed to " + where
			}
			if where == "" && ips.Free(env.Hosts, env.IPs, x)[h.Name] == 0 {
				return "no free extra address for IP " + name + " (kvoadm host addresses " + h.Name + " add CIDR)"
			}
			continue
		}
		follows := x.Status.Follows
		if c, ok := env.Classes[x.Spec.Class]; ok && c.Follows != "" {
			follows = c.Follows
		}
		if follows == kplugin.FollowsHost && x.Status.Host != "" && x.Status.Host != h.Name {
			return "IP " + name + "'s address stays on " + x.Status.Host + " (class " + x.Spec.Class + " can't move it)"
		}
		if follows != kplugin.FollowsGlobal && x.Status.Region != "" && (h.Status.Provider == nil || h.Status.Provider.Region != x.Status.Region) {
			return "IP " + name + "'s address is in " + x.Status.Region
		}
	}
	return ""
}

// Egress is where a silo placed on h sends from, given the address it's reached on (in) and the
// IPs it holds, and why that isn't in when it isn't: design §7.2b's table.
//
//   - hostPort, worker-ip: the host's address, for host and sameAsService alike;
//   - ip-pool, and a class whose address is on the silo's host (SendsFrom: an announced shared IP):
//     the IP's address with sameAsService (and egress.source pool: its own IP's);
//   - a balancer in front (not SendsFrom), or a class no plugin serves now: never the balancer's
//     address, which is on no host: the host's, with the reason.
func Egress(s *v1.Silo, h *v1.Host, in string, svcIP, egIP *v1.IP, classes map[string]Class) (out, note string) {
	hostOut := ""
	if !h.Spec.Network.BehindNAT {
		hostOut = h.Spec.Address
	}
	class := ""
	if sv := s.Spec.Service; sv != nil && sv.Expose == v1.ExposeLoadBalancer && sv.LoadBalancer != nil {
		class = sv.LoadBalancer.Class
	}
	c, served := classes[class]
	switch s.Spec.Network.Egress.Source {
	case v1.EgressPool:
		name := v1.SiloEgressIP(s)
		if egIP == nil || egIP.Status.Address == "" || egIP.Status.Host != h.Name {
			return hostOut, "waiting for IP " + name + "'s address: out is the host's meanwhile"
		}
		if in != "" && in != egIP.Status.Address {
			return egIP.Status.Address, "out is IP " + name + "'s own address (egress.source pool)"
		}
		return egIP.Status.Address, ""
	case v1.EgressSameAsService:
		switch {
		case UsesHostAddress(s):
			return hostOut, ""
		case class == v1.LBIPPool:
			if in == "" {
				return hostOut, "waiting for IP " + svcIPName(s) + "'s address: out is the host's meanwhile"
			}
			return in, ""
		case !served:
			return hostOut, "no plugin serves class " + class + " now, so nothing says its address can be sent from: out is the host's (sameAsService not applied)"
		case !c.SendsFrom:
			return hostOut, class + "'s address is its balancer's, on no host, so nothing can send from it: out is the host's (sameAsService can't be honoured)"
		case svcIP == nil || svcIP.Status.Address == "":
			return hostOut, "waiting for IP " + svcIPName(s) + "'s address: out is the host's meanwhile"
		}
		return svcIP.Status.Address, ""
	}
	if in == "" || in == hostOut {
		return hostOut, ""
	}
	note = "out is the host's address (egress.source host)"
	switch {
	case class == v1.LBIPPool || (served && c.SendsFrom):
		note += "; egress.source sameAsService sends from " + in
	case served && !c.SendsFrom:
		note += "; " + in + " is " + class + "'s balancer's, on no host, so nothing can send from it"
	}
	return hostOut, note
}

func ownedBy(x *v1.IP, uid string) bool {
	for _, r := range x.OwnerReferences {
		if r.UID == uid {
			return true
		}
	}
	return false
}
