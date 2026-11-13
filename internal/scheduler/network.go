package scheduler

import (
	"fmt"
	"slices"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// UsesHostAddress: the silo's exposed ports open on its host's own address (hostPort, worker-ip).
func UsesHostAddress(s *v1.Silo) bool {
	sv := s.Spec.Service
	if sv == nil {
		return false
	}
	return sv.Expose == v1.ExposeHostPort ||
		(sv.Expose == v1.ExposeLoadBalancer && sv.LoadBalancer != nil && sv.LoadBalancer.Class == v1.LBWorkerIP)
}

type hostPort struct {
	proto string
	port  int
}

// openedPorts are the host-address ports a silo claims.
func openedPorts(s *v1.Silo) []hostPort {
	if !UsesHostAddress(s) {
		return nil
	}
	var names []string
	if s.Spec.Service.Expose == v1.ExposeHostPort && s.Spec.Service.HostPort != nil {
		names = s.Spec.Service.HostPort.Ports
	}
	var out []hostPort
	for _, p := range s.Spec.Service.Ports {
		if len(names) > 0 && !contains(names, p.Name) {
			continue
		}
		proto := "TCP"
		if strings.EqualFold(p.Protocol, "UDP") {
			proto = "UDP"
		}
		out = append(out, hostPort{proto, p.Port})
	}
	return out
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// netFilter: the network rules a host must meet for the silo (empty: fine).
func netFilter(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) string {
	if UsesHostAddress(s) { // any host will do: its ports answer on whatever addresses it has (§7.2a)
		want := openedPorts(s)
		for _, o := range placed {
			if o.Status.Host != h.Name || (o.Namespace == s.Namespace && o.Name == s.Name) {
				continue
			}
			for _, a := range openedPorts(o) {
				for _, b := range want {
					if a == b {
						return fmt.Sprintf("port %d/%s already open for %s/%s", b.port, b.proto, o.Namespace, o.Name)
					}
				}
			}
		}
	}
	if why := ipFilter(s, h, env); why != "" {
		return why
	}
	return ""
}

// ServiceStatus is where a silo placed on h is reached and sends from, and its name. An IP's
// address is the IP's (design §7.2c-1): ip-pool's is set here; a plugin's class's is the plugin's
// (the load-balancer controller writes it; kept here), and node ports, if the class uses them,
// are allocated on h. The address out follows the table of §7.2b (Egress). Pure.
func ServiceStatus(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) (v1.SiloServiceStatus, error) {
	st := v1.SiloServiceStatus{Name: s.Name + "." + s.Namespace + ".kevaso"}
	svcName, _ := svcIPName(s, env)
	svcIP, egIP := heldIP(s, svcName, env), heldIP(s, v1.SiloEgressIP(s), env)
	if svcIP != nil {
		st.IP = svcIP.Name
	}
	if class := v1.PluginLB(s); class != "" {
		if svcIP != nil { // the balancer writes the address; a silo waiting for its IP has none
			cur := s.Status.Service
			st.PublicIP, st.SourceRanges, st.Announce = cur.PublicIP, cur.SourceRanges, cur.Announce
		}
		if c, ok := env.Classes[class]; ok && c.NodePorts {
			np, err := NodePorts(s, h.Name, placed)
			if err != nil {
				return st, err
			}
			st.NodePorts = np
		}
	}
	for _, x := range []*v1.IP{svcIP, egIP} {
		if x != nil && x.Spec.Class == v1.LBIPPool && x.Status.Address != "" && x.Status.Host == h.Name && !slices.Contains(st.HostAddresses, x.Status.Address) {
			st.HostAddresses = append(st.HostAddresses, x.Status.Address)
		}
	}
	switch {
	case UsesHostAddress(s):
		st.PublicIP = h.Reach()
	case svcIP != nil && svcIP.Spec.Class == v1.LBIPPool:
		if svcIP.Status.Host == h.Name {
			st.PublicIP = svcIP.Status.Address
		}
	}
	st.AnswersOn = AnswersOn(s, h, st.PublicIP)
	st.EgressIP, st.EgressNote = Egress(s, h, st.PublicIP, svcIP, egIP, env.Classes)
	return st, nil
}

// AnswersOn are the addresses s's exposed ports answer on, placed on h: for hostPort and worker-ip
// every address the host has (its main one first, then what its agent reports: LAN, behind NAT),
// whether public or not; otherwise the address it's reached on (its IP's), if any.
func AnswersOn(s *v1.Silo, h *v1.Host, in string) []string {
	if !UsesHostAddress(s) {
		if in == "" {
			return nil
		}
		return []string{in}
	}
	var out []string
	for _, a := range []string{h.Internal(), h.External()} {
		if a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// NodePorts gives each of s's service ports a host port on host, kept if it already has them there:
// the lowest free in v1.NodePortMin…NodePortSiloMax among the silos placed on host.
func NodePorts(s *v1.Silo, host string, placed []*v1.Silo) ([]v1.NodePort, error) {
	if s.Spec.Service == nil {
		return nil, nil
	}
	taken := map[int]bool{}
	for _, o := range placed {
		if o.Status.Host != host || (o.Namespace == s.Namespace && o.Name == s.Name) {
			continue
		}
		for _, p := range o.Status.Service.NodePorts {
			taken[p.NodePort] = true
		}
	}
	had := map[string]int{}
	if s.Status.Host == host {
		for _, p := range s.Status.Service.NodePorts {
			if !taken[p.NodePort] {
				had[p.Name] = p.NodePort
			}
		}
	}
	for _, p := range had {
		taken[p] = true
	}
	var out []v1.NodePort
	next := v1.NodePortMin
	for _, p := range s.Spec.Service.Ports {
		np, ok := had[p.Name]
		if !ok {
			for next <= v1.NodePortSiloMax && taken[next] {
				next++
			}
			if next > v1.NodePortSiloMax {
				return nil, fmt.Errorf("no free node port on %s", host)
			}
			np = next
			taken[np] = true
		}
		out = append(out, v1.NodePort{Name: p.Name, Port: p.Port, NodePort: np})
	}
	return out, nil
}
