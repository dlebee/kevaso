package worker

import (
	"net/netip"
	"slices"
	"sort"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
)

// IPs on a worker (networking v2): a silo's HostPort on an IP (hostPort ip or own) opens on that
// IP's address, and egress.source ip or own sends from it, only while the silo holds the IP and
// the address is on this host: a Host IP whose host is this one, or a Provider IP whose holder
// runs here (the worker announces it). Read from the IP objects themselves, not a status copy.
// One IP, one family (the IPv6 effort): a Host IP may be IPv6 (an IPv6 host address); Provider
// IPs here are IPv4 only (no provider floats single IPv6 addresses yet).

// ipHere is the IP named name (in s's namespace) when s holds it and its address is on this host.
func ipHere(hostName string, s *v1.Silo, name string, ips []*v1.IP) (netip.Addr, bool) {
	for _, x := range ips {
		if x.Namespace == s.Namespace && x.Name == name {
			return addrHere(hostName, s, x)
		}
	}
	return netip.Addr{}, false
}

// ownHere is the SiloSet instance's own IPSet member (an IP labelled with its set, held by s),
// when its address is on this host. Several: the first by name (one holder each, so it's one).
func ownHere(hostName string, s *v1.Silo, ips []*v1.IP) (netip.Addr, bool) {
	var mine []*v1.IP
	for _, x := range ips {
		if x.Namespace == s.Namespace && x.Labels[v1.LabelIPSet] != "" && x.Status.Holds(s.UID) {
			mine = append(mine, x)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Name < mine[j].Name })
	for _, x := range mine {
		if a, ok := addrHere(hostName, s, x); ok {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// addrHere is x's address when s holds it and it is on this host now.
func addrHere(hostName string, s *v1.Silo, x *v1.IP) (netip.Addr, bool) {
	if s.Status.Host != hostName || s.DeletionTimestamp != nil || !x.Status.Holds(s.UID) {
		return netip.Addr{}, false
	}
	a, ok := hostAddr(x.Status.Address)
	if !ok {
		return netip.Addr{}, false
	}
	switch x.Spec.Type {
	case v1.IPTypeHost:
		if x.Status.Host != hostName {
			return netip.Addr{}, false
		}
	case v1.IPTypeProvider: // its holder runs here: this worker announces it
		if !a.Is4() {
			return netip.Addr{}, false
		}
	default:
		return netip.Addr{}, false
	}
	return a, true
}

// serviceAddrs are where s's HostPort services on an IP open on this host, by service name.
func serviceAddrs(hostName string, s *v1.Silo, ips []*v1.IP) map[string]netip.Addr {
	var out map[string]netip.Addr
	for _, sv := range s.Spec.Services {
		way := sv.Way()
		var a netip.Addr
		var ok bool
		switch {
		case way.IP != "":
			a, ok = ipHere(hostName, s, way.IP, ips)
		case way.Own:
			a, ok = ownHere(hostName, s, ips)
		}
		if ok {
			if out == nil {
				out = map[string]netip.Addr{}
			}
			out[v1.ServiceNameOf(sv, s.Name)] = a
		}
	}
	return out
}

// egressHere is where s's traffic leaves from on this host: egress.source's IP when it is here
// (invalid otherwise: the worker's own address). A balancer's IP (loadBalancer.ip) never sends.
// The address's family is the one it applies to (an IPv6 IP sets the IPv6 source only).
func egressHere(hostName string, s *v1.Silo, ips []*v1.IP) netip.Addr {
	src := s.Spec.Network.Egress.Source
	if src == nil {
		return netip.Addr{}
	}
	switch {
	case src.IP != "":
		if slices.ContainsFunc(s.Spec.Services, func(sv v1.SiloService) bool { return sv.LoadBalancer != nil && sv.LoadBalancer.IP == src.IP }) {
			return netip.Addr{}
		}
		if a, ok := ipHere(hostName, s, src.IP, ips); ok {
			return a
		}
	case src.Own:
		if a, ok := ownHere(hostName, s, ips); ok {
			return a
		}
	}
	return netip.Addr{}
}

// HeldAddresses are the addresses of the IPs this host's silos hold here (hostPort ip or own,
// egress.source): they go on its uplink, as /32s (IPv6: /128s), with the status's host addresses. A Provider
// IP whose provider announces it (status.announce) goes on the loopback instead
// (AnnouncedIPAddresses).
func HeldAddresses(hostName string, silos []*v1.Silo, ips []*v1.IP) []string {
	return heldAddresses(hostName, silos, ips, false)
}

// AnnouncedIPAddresses are the held addresses of Provider IPs whose provider announces them:
// they go on the loopback, where the provider's node side announces them (BGP).
func AnnouncedIPAddresses(hostName string, silos []*v1.Silo, ips []*v1.IP) []string {
	return heldAddresses(hostName, silos, ips, true)
}

func announced(ips []*v1.IP, a netip.Addr) bool {
	return slices.ContainsFunc(ips, func(x *v1.IP) bool {
		return x.Spec.Type == v1.IPTypeProvider && x.Status.Announce && x.Status.Address == a.String()
	})
}

func heldAddresses(hostName string, silos []*v1.Silo, ips []*v1.IP, announce bool) []string {
	var out []string
	add := func(a netip.Addr, ok bool) {
		if ok && announced(ips, a) == announce && !slices.Contains(out, a.String()) {
			out = append(out, a.String())
		}
	}
	for _, s := range silos {
		if s.Status.Host != hostName {
			continue
		}
		for _, a := range serviceAddrs(hostName, s, ips) {
			add(a, true)
		}
		e := egressHere(hostName, s, ips)
		add(e, e.IsValid())
	}
	sort.Strings(out)
	return out
}

// WithIPs puts the IPs into this host's view: each local silo's HostPort addresses on an IP and
// its address out, and every extra address this host has (its named ones, the held ones) as an
// address no silo reaches the host on. Pure.
func WithIPs(view kni.Host, hostName string, me *v1.Host, silos []*v1.Silo, ips []*v1.IP) kni.Host {
	byKey := map[string]*v1.Silo{}
	for _, s := range silos {
		byKey[s.Namespace+"/"+s.Name] = s
	}
	local := make([]kni.Silo, len(view.Local))
	copy(local, view.Local)
	for i, ks := range local {
		s, ok := byKey[ks.Key]
		if !ok {
			continue
		}
		ks.Addrs = serviceAddrs(hostName, s, ips)
		ks.EgressIP, ks.EgressIPv6 = netip.Addr{}, netip.Addr{}
		if e := egressHere(hostName, s, ips); e.Is4() {
			ks.EgressIP = e
		} else if e.IsValid() {
			ks.EgressIPv6 = e
		}
		local[i] = ks
	}
	view.Local = local
	own := append([]netip.Addr(nil), view.OwnIPs...)
	addOwn := func(s string) {
		if a, ok := hostAddr(s); ok && !slices.Contains(own, a) {
			own = append(own, a)
		}
	}
	if me != nil {
		for _, ad := range me.Spec.Addresses {
			addOwn(ad.Address)
		}
	}
	for _, a := range HeldAddresses(hostName, silos, ips) {
		addOwn(a)
	}
	for _, a := range PoolAddresses(hostName, silos) {
		addOwn(a)
	}
	slices.SortFunc(own, func(x, y netip.Addr) int { return x.Compare(y) })
	view.OwnIPs = own
	return view
}
