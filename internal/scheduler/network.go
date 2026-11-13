package scheduler

import (
	"fmt"
	"net/netip"

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

// PoolOf is the IPPool the silo takes an address from ("" if none): its load balancer's, or its
// egress's (admission makes them the same when both are set).
func PoolOf(s *v1.Silo) string {
	if sv := s.Spec.Service; sv != nil && sv.Expose == v1.ExposeLoadBalancer && sv.LoadBalancer != nil && sv.LoadBalancer.Class == v1.LBIPPool {
		return sv.LoadBalancer.Pool
	}
	if s.Spec.Network.Egress.Source == v1.EgressPool {
		return s.Spec.Network.Egress.Pool
	}
	return ""
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

// PoolAddresses lists a pool's addresses, in order.
func PoolAddresses(p *v1.IPPool) []netip.Addr {
	var out []netip.Addr
	for _, a := range p.Spec.Addresses {
		if addr, err := netip.ParseAddr(a); err == nil {
			out = append(out, addr)
			continue
		}
		pfx, err := netip.ParsePrefix(a)
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		if pfx.Bits() >= 31 { // /31, /32: every address is usable
			for x := pfx.Addr(); pfx.Contains(x); x = x.Next() {
				out = append(out, x)
			}
			continue
		}
		last := pfx.Addr()
		for x := pfx.Addr(); pfx.Contains(x); x = x.Next() {
			last = x
		}
		for x := pfx.Addr().Next(); x.Compare(last) < 0; x = x.Next() { // skip network and broadcast
			out = append(out, x)
		}
	}
	return out
}

// FreePoolAddress is the lowest address of pool no other silo holds.
func FreePoolAddress(pool *v1.IPPool, self *v1.Silo, placed []*v1.Silo) (netip.Addr, bool) {
	held := map[string]bool{}
	for _, s := range placed {
		if s.Namespace == self.Namespace && s.Name == self.Name {
			continue
		}
		if ip := s.Status.Service.PoolIP; ip != "" {
			held[ip] = true
		}
	}
	for _, a := range PoolAddresses(pool) {
		if !held[a.String()] {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func poolByName(pools []*v1.IPPool, name string) *v1.IPPool {
	for _, p := range pools {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// netFilter: the network rules a host must meet for the silo (empty: fine).
func netFilter(s *v1.Silo, h *v1.Host, placed []*v1.Silo, pools []*v1.IPPool) string {
	if UsesHostAddress(s) {
		if h.Spec.Network.BehindNAT {
			return "behind NAT: no public address to open ports on"
		}
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
	if name := PoolOf(s); name != "" {
		p := poolByName(pools, name)
		switch {
		case p == nil:
			return "IPPool " + name + " doesn't exist"
		case p.Spec.Host != h.Name:
			return "IPPool " + name + " is routed to " + p.Spec.Host
		}
		if _, ok := FreePoolAddress(p, s, placed); !ok && s.Status.Service.PoolIP == "" {
			return "IPPool " + name + " has no free address"
		}
	}
	return ""
}

// ServiceStatus is where a silo placed on h is reached and sends from, and its name. A pool address
// it already holds stays its own (stableIP). For a plugin's load-balancer class, the address is the
// plugin's (the load-balancer controller writes it; kept here), and node ports, if the class uses
// them, are allocated on h. Pure.
func ServiceStatus(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) (v1.SiloServiceStatus, error) {
	pools := env.Pools
	st := v1.SiloServiceStatus{Name: s.Name + "." + s.Namespace + ".kevaso"}
	if class := v1.PluginLB(s); class != "" {
		cur := s.Status.Service
		st.PublicIP, st.SourceRanges, st.Announce = cur.PublicIP, cur.SourceRanges, cur.Announce
		if c, ok := env.Classes[class]; ok && c.NodePorts {
			np, err := NodePorts(s, h.Name, placed)
			if err != nil {
				return st, err
			}
			st.NodePorts = np
		}
	}
	if name := PoolOf(s); name != "" {
		p := poolByName(pools, name)
		if p == nil {
			return st, fmt.Errorf("IPPool %s doesn't exist", name)
		}
		if cur := s.Status.Service.PoolIP; cur != "" && containsAddr(PoolAddresses(p), cur) {
			st.PoolIP = cur
		} else if a, ok := FreePoolAddress(p, s, placed); ok {
			st.PoolIP = a.String()
		} else {
			return st, fmt.Errorf("IPPool %s has no free address", name)
		}
	}
	switch {
	case UsesHostAddress(s):
		st.PublicIP = h.Spec.Address
	case s.Spec.Service != nil && s.Spec.Service.Expose == v1.ExposeLoadBalancer && st.PoolIP != "":
		st.PublicIP = st.PoolIP
	}
	switch s.Spec.Network.Egress.Source {
	case v1.EgressSameAsService:
		st.EgressIP = st.PublicIP
	case v1.EgressPool:
		st.EgressIP = st.PoolIP
	default:
		if !h.Spec.Network.BehindNAT {
			st.EgressIP = h.Spec.Address
		}
	}
	return st, nil
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

func containsAddr(l []netip.Addr, s string) bool {
	for _, a := range l {
		if a.String() == s {
			return true
		}
	}
	return false
}
