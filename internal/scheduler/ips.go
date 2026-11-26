package scheduler

import (
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
)

// TODO(net-v2 wave 2): placement follows the address (networking v2 "Rules"): worker anywhere, a
// Host IP pinned to its host, a Provider IP and load balancers within the provider's reach, own
// by the instance's IPSet member, several ways in intersected, and "can move: … (why)". What is
// here is the minimum that keeps the old guarantees: an IP is held before its silo is placed, and
// its address only goes where it can be.

// balancerProvider is the provider of the silo's first LoadBalancer service ("" if none).
// TODO(net-v2 wave 2): one balancer per service; the plugin's capabilities, not its class map.
func balancerProvider(s *v1.Silo) string {
	if b := s.Spec.Balancers(); len(b) > 0 && b[0].LoadBalancer != nil {
		return b[0].LoadBalancer.Provider
	}
	return ""
}

// providerUsesNodePorts says whether the provider's balancer sends to the host on node ports
// (one of its plugin's load-balancer classes says so).
// TODO(net-v2 wave 2): the provider's declared capability, not its classes.
func providerUsesNodePorts(classes map[string]Class, provider string) bool {
	for _, c := range classes {
		if c.Plugin == provider && c.NodePorts {
			return true
		}
	}
	return false
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
// IP first; a Host IP only goes on the host with its address; a Provider IP only on that
// provider's machines in its region.
func ipFilter(s *v1.Silo, h *v1.Host, env Env) string {
	for _, name := range v1.SiloIPs(s) {
		x := findIP(env, s.Namespace, name)
		switch {
		case x == nil:
			return "IP " + name + " doesn't exist"
		case !x.Status.Holds(s.UID):
			if why := x.Status.WaitingReason(s.UID); why != "" {
				return why
			}
			return "waiting for IP " + name + " to be bound to it"
		}
		switch x.Spec.Type {
		case v1.IPTypeHost:
			where := x.Status.Host
			if where == "" {
				if hh, _, ok := ips.FindAddress(env.Hosts, x.Spec.HostAddress); ok {
					where = hh.Name
				}
			}
			if where == "" {
				return "no host has address " + x.Spec.HostAddress + " (kvoadm host addresses HOST add " + x.Spec.HostAddress + " ADDRESS)"
			}
			if where != h.Name {
				return "IP " + name + " is host " + where + "'s address"
			}
		case v1.IPTypeProvider:
			if p := h.Status.Provider; p == nil || p.Name != x.Spec.Provider || p.Region != x.Spec.Region {
				return "IP " + name + " is " + x.Spec.Provider + "'s, in " + x.Spec.Region
			}
		}
	}
	return ""
}

// Egress is where a silo placed on h sends from, and why that isn't where it's reached when it
// isn't: the worker's own address by default; egress.source.ip that IP's address, once it holds
// it and it's on h.
// TODO(net-v2 wave 2): egress.source own (the instance's IPSet member); a balancer's IP can't
// send out.
func Egress(s *v1.Silo, h *v1.Host, st v1.SiloServiceStatus, egIP *v1.IP) (out, note string) {
	hostOut := ""
	if !h.Spec.Network.BehindNAT {
		hostOut = h.Reach()
	}
	src := s.Spec.Network.Egress.Source
	switch {
	case src != nil && src.IP != "":
		if egIP == nil || egIP.Status.Address == "" || egIP.Status.Host != h.Name {
			return hostOut, "waiting for IP " + src.IP + "'s address: out is the worker's meanwhile"
		}
		return egIP.Status.Address, ""
	case src != nil && src.Own:
		return hostOut, "egress.source own isn't applied yet: out is the worker's"
	}
	if in := st.LoadBalancerIP; in != "" && in != hostOut {
		return hostOut, "out is the worker's address (no egress.source)"
	}
	return hostOut, ""
}
