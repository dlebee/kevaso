package scheduler

import (
	v1 "kevaso.com/core/api/v1"
)

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

// Egress is where a silo placed on h sends from, and why that isn't where it's reached when it
// isn't: the worker's own address by default; egress.source.ip that IP's address, once it holds
// it and it's on h.
// egress.source own the instance's IPSet member's, the same way. egIP is the IP it names (or its
// own member), as held.
func Egress(s *v1.Silo, h *v1.Host, st v1.SiloServiceStatus, egIP *v1.IP) (out, note string) {
	hostOut := ""
	if !h.Spec.Network.BehindNAT {
		hostOut = h.Reach()
	}
	src := s.Spec.Network.Egress.Source
	if src != nil && (src.IP != "" || src.Own) {
		what := "IP " + src.IP
		if src.Own {
			what = "its IPSet member"
			if egIP != nil {
				what += " (IP " + egIP.Name + ")"
			}
		}
		if egIP == nil || egIP.Status.Address == "" || egIP.Status.Host != h.Name {
			return hostOut, "waiting for " + what + "'s address: out is the worker's meanwhile"
		}
		return egIP.Status.Address, ""
	}
	if in := st.LoadBalancerIP; in != "" && in != hostOut {
		return hostOut, "out is the worker's address (no egress.source)"
	}
	return hostOut, ""
}
