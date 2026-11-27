package scheduler

import (
	"fmt"
	"maps"
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

// AddedHostPorts are the host ports in next that old does not already open, in next's order,
// without duplicates. A placed silo's update claims these before it is stored.
func AddedHostPorts(old, next v1.SiloSpec) []HostPort {
	have := map[HostPort]bool{}
	for _, p := range HostPorts(&v1.Silo{Spec: old}) {
		have[p] = true
	}
	var out []HostPort
	seen := map[HostPort]bool{}
	for _, p := range HostPorts(&v1.Silo{Spec: next}) {
		if have[p] || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// missingAddress is the first of the silo's worker host ports h has no address for (ok false:
// it has them all).
func missingAddress(s *v1.Silo, h *v1.Host) (HostPort, bool) {
	for _, w := range HostPorts(s) {
		if h.IPOn(w.Network) == "" {
			return w, true
		}
	}
	return HostPort{}, false
}

// netFilter: the network rules a host must meet for the silo (empty: fine). A port with
// hostPort needs the host to have that address, and no other silo there holding the same address
// and number. (Where its kept addresses can be is addressLimits'.)
func netFilter(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) string {
	want := HostPorts(s)
	if w, ok := missingAddress(s, h); ok {
		return fmt.Sprintf("no %s IP, which port %d/%s asks for (hostPort: [%s])", w.Network, w.Port, w.Proto, w.Network)
	}
	for _, w := range want {
		if env.Claimed[h.Name].HostPorts[w] {
			return fmt.Sprintf("port %s (%s) is held by another silo", w, h.IPOn(w.Network))
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
	return ""
}

// ServiceStatus is where a silo placed on h is reached and sends from, and its name. A Host IP's
// address goes on h's uplink; a balancer's is the balancer controller's (kept here), and node
// ports, if the provider uses them, are allocated on h. The address out is Egress's. Pure.
// TODO(net-v2 wave 2): one status per service.
func ServiceStatus(s *v1.Silo, h *v1.Host, placed []*v1.Silo, env Env) (v1.SiloServiceStatus, error) {
	var st v1.SiloServiceStatus
	if len(s.Spec.Services) > 0 { // no service, no name: only where its own traffic comes from
		st.Name = v1.ServiceDNSName(v1.ServiceName(s), s.Namespace, "", env.Suffix)
	}
	var lbIP *v1.IP
	for _, sv := range s.Spec.Balancers() {
		if sv.LoadBalancer != nil && sv.LoadBalancer.IP != "" {
			lbIP = heldIP(s, sv.LoadBalancer.IP, env)
		}
	}
	var egIP *v1.IP
	if src := s.Spec.Network.Egress.Source; src != nil {
		egIP = heldIP(s, src.IP, env)
		if src.Own {
			egIP = OwnIP(s, env)
		}
	}
	if lbIP != nil {
		st.IP = lbIP.Name
	}
	if s.Spec.LoadBalanced() {
		cur := s.Status.Service // the balancer writes the address; kept here
		st.LoadBalancerIP, st.LoadBalancerIPv6, st.SourceRanges, st.Announce = cur.LoadBalancerIP, cur.LoadBalancerIPv6, cur.SourceRanges, cur.Announce
		if providerUsesNodePorts(env.Classes, balancerProvider(s)) {
			np, err := nodePorts(s, h.Name, placed, env.Claimed[h.Name].NodePorts)
			if err != nil {
				return st, err
			}
			st.NodePorts = np
		}
	}
	// A Host IP the silo holds on h is put on h's uplink.
	// TODO(net-v2 wave 2): hostPort.ip opens its ports on that address (the agent's rules).
	var held []*v1.IP
	for _, name := range v1.SiloIPs(s) {
		held = append(held, heldIP(s, name, env))
	}
	held = append(held, OwnIP(s, env))
	for _, x := range held {
		if x != nil && x.Spec.Type == v1.IPTypeHost && x.Status.Address != "" && x.Status.Host == h.Name && !slices.Contains(st.HostAddresses, x.Status.Address) {
			st.HostAddresses = append(st.HostAddresses, x.Status.Address)
		}
	}
	st.Ports = PortStatusWith(s, h, st.LoadBalancerIP, func(p v1.OpenPort) *v1.IP {
		if p.Way.Own {
			return OwnIP(s, env)
		}
		return heldIP(s, p.Way.IP, env)
	})
	family := sourceFamily(s, env)
	st.EgressIP, st.EgressNote = Egress(s, h, st, egIP, family)
	st.EgressIPv6 = EgressIPv6(s, h, egIP, family)
	return st, nil
}

// PortStatus is where each of s's service ports is reachable, placed on h: its silo IP (when it
// has one), the host's internal and external IPs its hostPort asks for, the load-balancer
// address lb. Pure.
func PortStatus(s *v1.Silo, h *v1.Host, lb string) []v1.ServicePortStatus {
	return PortStatusWith(s, h, lb, nil)
}

// PortStatusWith is PortStatus, and a HostPort port on an IP (hostPort ip or own) at that IP's
// address while the silo holds it on h: held is the IP the port names, as held (nil: not held).
// It goes in internal or external as the IP is: a host's address of that kind, a provider's
// external. Pure.
func PortStatusWith(s *v1.Silo, h *v1.Host, lb string, held func(v1.OpenPort) *v1.IP) []v1.ServicePortStatus {
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
		if (p.Way.IP != "" || p.Way.Own) && held != nil {
			if x := held(p); x != nil && x.Status.Address != "" && x.Status.Host == h.Name {
				kind := v1.NetworkExternal
				if x.Spec.Type == v1.IPTypeHost {
					if a, ok := h.Address(x.Spec.HostAddress); ok && a.Kind == v1.NetworkInternal {
						kind = v1.NetworkInternal
					}
				}
				if kind == v1.NetworkInternal {
					ps.Internal = at(x.Status.Address, p.HostNumber())
				} else {
					ps.External = at(x.Status.Address, p.HostNumber())
				}
			}
		}
		out = append(out, ps)
	}
	return out
}

// SetLoadBalancerIP puts lb (empty: none) as s's load-balancer address in st: loadBalancerIP and
// each load-balanced port's loadBalancer, as PortStatus says them, so one write never leaves the
// two disagreeing (an address in with no port on it, or a port on an address taken away).
//
// st.Ports has one entry per service port (PortStatus): a declared port in two services is two
// entries, each at its own service's as number. They are matched by position when they line up
// with the spec's, so two LoadBalancer services on one port keep their own numbers (by name
// alone both took the first's, and the scheduler's write put them back: a write storm).
func SetLoadBalancerIP(s *v1.Silo, st *v1.SiloServiceStatus, lb string) {
	st.LoadBalancerIP = lb
	open := s.Spec.Open()
	aligned := len(open) == len(st.Ports)
	for i, ps := range st.Ports {
		if aligned && open[i].Name != ps.Port {
			aligned = false
		}
	}
	for i, ps := range st.Ports {
		p, ok := s.Spec.OpenPort(ps.Port)
		if aligned {
			p, ok = open[i], true
		}
		if ok && p.LoadBalancer {
			st.Ports[i].LoadBalancer = ""
			if lb != "" {
				st.Ports[i].LoadBalancer = net.JoinHostPort(lb, strconv.Itoa(p.HostNumber()))
			}
		}
	}
}

// NodePorts gives each of s's service ports a host port on host, kept if it already has them there:
// the lowest free in v1.NodePortMin…NodePortSiloMax among the silos placed on host.
func NodePorts(s *v1.Silo, host string, placed []*v1.Silo) ([]v1.NodePort, error) {
	return nodePorts(s, host, placed, nil)
}

// nodePorts is NodePorts, also avoiding the ports in avoid (held by others, says the store).
func nodePorts(s *v1.Silo, host string, placed []*v1.Silo, avoid map[int]bool) ([]v1.NodePort, error) {
	if !s.Spec.LoadBalanced() {
		return nil, nil
	}
	taken := maps.Clone(avoid)
	if taken == nil {
		taken = map[int]bool{}
	}
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
