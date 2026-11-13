package scheduler

import (
	"fmt"
	"net"
	"slices"
	"strconv"

	v1 "kevaso.com/core/api/v1"
)

// HostPort is one number a silo holds on one of its host's addresses: its network (internal or
// external), the protocol and the number (as).
type HostPort struct {
	Network string
	Proto   string
	Port    int
}

func (p HostPort) String() string {
	return fmt.Sprintf("%d/%s on the %s IP", p.Port, p.Proto, p.Network)
}

// HostPorts are the numbers a silo holds on its host's addresses (design §7.0: hostPort, as),
// leased ones included (a closed port still has its number).
func HostPorts(s *v1.Silo) []HostPort {
	var out []HostPort
	for _, p := range s.Spec.Open() {
		for _, n := range p.HostPort {
			out = append(out, HostPort{n, p.Protocol, p.HostNumber()})
		}
	}
	return out
}

// netFilter: the network rules a host must meet for the silo (empty: fine). A port with
// hostPort needs the host to have that address, and no other silo there holding the same address
// and number.
func netFilter(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) string {
	want := HostPorts(s)
	for _, w := range want {
		if h.IPOn(w.Network) == "" {
			return fmt.Sprintf("no %s IP, which port %d/%s asks for (hostPort: [%s])", w.Network, w.Port, w.Proto, w.Network)
		}
	}
	if len(want) > 0 {
		for _, o := range placed {
			if o.Status.Host != h.Name || (o.Namespace == s.Namespace && o.Name == s.Name) || o.DeletionTimestamp != nil {
				continue
			}
			for _, a := range HostPorts(o) {
				if slices.Contains(want, a) {
					return fmt.Sprintf("port %s (%s) is held by %s/%s", a, h.IPOn(a.Network), o.Namespace, o.Name)
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
	var st v1.SiloServiceStatus
	if s.Spec.Service != nil { // no service, no name: only where its own traffic comes from
		st.Name = v1.ServiceDNSName(v1.ServiceName(s), s.Namespace, "", env.Suffix)
	}
	svcName, _ := svcIPName(s, env)
	svcIP, egIP := heldIP(s, svcName, env), heldIP(s, v1.SiloEgressIP(s), env)
	if svcIP != nil {
		st.IP = svcIP.Name
	}
	if class := v1.PluginLB(s); class != "" {
		if svcIP != nil { // the balancer writes the address; a silo waiting for its IP has none
			cur := s.Status.Service
			st.LoadBalancerIP, st.SourceRanges, st.Announce = cur.LoadBalancerIP, cur.SourceRanges, cur.Announce
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
	if svcIP != nil && svcIP.Spec.Class == v1.LBIPPool && svcIP.Status.Host == h.Name {
		st.LoadBalancerIP = svcIP.Status.Address
	}
	st.Ports = PortStatus(s, h, st.LoadBalancerIP)
	st.EgressIP, st.EgressNote = Egress(s, h, st, svcIP, egIP, env.Classes)
	return st, nil
}

// PortStatus is where each of s's service ports is reachable, placed on h: its silo IP (when it
// has one), the host's internal and external IPs its hostPort asks for, the load-balancer
// address lb. Pure.
func PortStatus(s *v1.Silo, h *v1.Host, lb string) []v1.ServicePortStatus {
	var out []v1.ServicePortStatus
	at := func(ip string, port int) string {
		if ip == "" {
			return ""
		}
		return net.JoinHostPort(ip, strconv.Itoa(port))
	}
	for _, p := range s.Spec.Open() {
		ps := v1.ServicePortStatus{Port: p.Name, Mesh: at(s.Status.SiloIP, p.Number)}
		if p.On(v1.NetworkInternal) {
			ps.Internal = at(h.Internal(), p.HostNumber())
		}
		if p.On(v1.NetworkExternal) {
			ps.External = at(h.External(), p.HostNumber())
		}
		if p.LoadBalancer {
			ps.LoadBalancer = at(lb, p.HostNumber())
		}
		out = append(out, ps)
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
	for _, p := range s.Spec.Open() {
		if !p.LoadBalancer {
			continue
		}
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
		out = append(out, v1.NodePort{Name: p.Name, Port: p.Number, NodePort: np})
	}
	return out, nil
}
