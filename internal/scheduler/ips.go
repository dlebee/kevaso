package scheduler

import (
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/sdk/kplugin"
)

// Exclusive reports whether a load-balancer class's address is one host's at a time (ip-pool,
// or a plugin's class that says so), so it's never shared between services.
func Exclusive(class string, classes map[string]Class) bool {
	return class == v1.LBIPPool || classes[class].Exclusive
}

// ExclusiveIn is Exclusive over classes, as a function (for v1.SiloIPs).
func ExclusiveIn(classes map[string]Class) func(string) bool {
	return func(c string) bool { return Exclusive(c, classes) }
}

// svcIPName is the IP the silo's service has its address from ("" if none), and how.
func svcIPName(s *v1.Silo, env Env) (string, v1.IPWay) {
	if sv := s.Spec.Service; sv != nil && sv.LoadBalancer != nil {
		return v1.SiloServiceIP(s, Exclusive(sv.LoadBalancer.Class, env.Classes))
	}
	return "", v1.IPNone
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
	if x := findIP(env, s.Namespace, name); x != nil && x.Status.Holds(s.UID) {
		return x
	}
	return nil
}

// ipFilter: the rules a host must meet for the silo's IPs (empty: fine). The silo must hold each
// IP first; an ip-pool address only goes on the host it's routed to (or, not reserved yet, a host
// with one free); a plugin's address only where its class lets it follow (its region, by default).
func ipFilter(s *v1.Silo, h *v1.Host, env Env) string {
	for _, name := range v1.SiloIPs(s, ExclusiveIn(env.Classes)) {
		x := findIP(env, s.Namespace, name)
		n, way := svcIPName(s, env)
		switch {
		case x == nil:
			if n == name && way != v1.IPNamed {
				return "waiting for IP " + name + " to be made"
			}
			return "IP " + name + " doesn't exist"
		case !x.Status.Holds(s.UID):
			if why := x.Status.WaitingReason(s.UID); why != "" {
				return why
			}
			if n == name && way == v1.IPMade && !ownedBy(x, s.UID) {
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
				n, _ := v1.SiloServiceIP(s, true)
				return hostOut, "waiting for IP " + n + "'s address: out is the host's meanwhile"
			}
			return in, ""
		case !served:
			return hostOut, "no plugin serves class " + class + " now, so nothing says its address can be sent from: out is the host's (sameAsService not applied)"
		case !c.SendsFrom:
			return hostOut, class + "'s address is its balancer's, on no host, so nothing can send from it: out is the host's (sameAsService can't be honoured)"
		case svcIP == nil || svcIP.Status.Address == "":
			n, _ := v1.SiloServiceIP(s, Exclusive(class, classes))
			return hostOut, "waiting for IP " + n + "'s address: out is the host's meanwhile"
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
