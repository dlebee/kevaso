package kni

import (
	"math/rand"
	"net/netip"
	"slices"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// IPv6 at the edge (the IPv6 effort): every rule that opens something has its IPv6 twin, and
// nothing else passes over IPv6. The mesh stays IPv4, so no silo reaches another silo over IPv6.
//
// The property is judged by the evaluator on one ruleset holding both families: a cluster is
// generated as for the IPv4 properties, then given an IPv6 twin of each of its addresses (its
// mirror: an IPv4 address a.b.c.d is ...:a.b.c.d in a /96 of its own, so containment is kept
// and every IPv6 source range is the twin of an IPv4 one). An IPv6 packet must then do exactly
// what its IPv4 mirror does on the host's addresses, never more anywhere else.

// The mirror's two /96s: silo addresses in a ULA (like the cluster's), everything else global.
var (
	mirrorSilo  = netip.MustParsePrefix("fd64:6464:6464::/96")
	mirrorWorld = netip.MustParsePrefix("2001:db8:ffff::/96")
	silos4      = netip.MustParsePrefix(silosAll)
)

// mirror6 is a's IPv6 twin.
func mirror6(a netip.Addr) netip.Addr {
	base := mirrorWorld
	if silos4.Contains(a) {
		base = mirrorSilo
	}
	b, v := base.Addr().As16(), a.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b)
}

func mirror6P(p netip.Prefix) netip.Prefix { return netip.PrefixFrom(mirror6(p.Addr()), 96+p.Bits()) }

// unmirror is a6's IPv4 twin (ok false: it has none).
func unmirror(a6 netip.Addr) (netip.Addr, bool) {
	if a6 == v6Nowhere {
		return v4Nowhere, true
	}
	if !mirrorSilo.Contains(a6) && !mirrorWorld.Contains(a6) {
		return netip.Addr{}, false
	}
	b := a6.As16()
	return netip.AddrFrom4([4]byte(b[12:])), true
}

// A client outside every mirrored range, and its IPv4 twin outside every range the generator
// uses (and inside a grant of 0.0.0.0/0, whose twin is ::/0).
var (
	v6Nowhere = a("2001:db8:5::7")
	v4Nowhere = a("198.18.0.1")
)

func mirrorSources(items []string) []string {
	out := append([]string(nil), items...)
	for _, it := range items {
		if p, err := netip.ParsePrefix(it); err == nil {
			out = append(out, mirror6P(p).String())
		} else if b, err := netip.ParseAddr(it); err == nil {
			out = append(out, mirror6(b).String())
		}
	}
	return out
}

// The IPv4 kept IP and grants a generated silo may have, beyond genClusterOf's.
var (
	propKept   = a("198.51.100.30")
	propGrants = []string{"0.0.0.0/0", "203.0.113.0/24", "192.0.2.7/32", "198.51.100.0/25", "10.0.0.0/8"}
	// Destinations outside the cluster for the egress check: public, the host's LAN, and nowhere.
	propOut = []netip.Addr{a("203.0.113.4"), a("192.0.2.7"), a("198.51.100.99"), a("10.0.0.9"), v4Nowhere}
)

// v6Cluster is a generated cluster (IPv4 only, with a kept IP and grants added) and its IPv6
// twin: the same host given IPv6 where the mirror says, some silos left without.
func v6Cluster(r *rand.Rand) (base, h6 Host) {
	g := portCluster(r)
	base = g.h
	// A kept IPv4 IP for one silo with a port, its twin for the IPv6 host.
	keptOn := -1
	for i, s := range base.Local {
		if len(s.Spec.Ports) > 0 && s.IP.IsValid() && r.Intn(2) == 0 {
			keptOn = i
			break
		}
	}
	for i := range base.Local {
		s := &base.Local[i]
		s.Spec = cloneSpec(s.Spec)
		if s.IP.IsValid() {
			for _, gr := range pickN(r, propGrants, 2) {
				e := v1.ParsedEgress{Prefix: netip.MustParsePrefix(gr), Protocols: pickN(r, []string{"tcp", "udp"}, 2)}
				switch r.Intn(3) {
				case 0:
					e.Ports = []v1.PortRange{{From: 443, To: 443}}
				case 1:
					e.Ports = []v1.PortRange{{From: 80, To: 90}}
				}
				s.Egress = append(s.Egress, e)
			}
		}
		if i == keptOn {
			p := s.Spec.Ports[0]
			sp := v1.ServicePort{Port: p.Name, Sources: pickN(r, propSources, 2)}
			s.Spec.Services = append(s.Spec.Services, v1.SiloService{Name: "kept", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge"}, Ports: []v1.ServicePort{sp}})
			s.Addrs = map[string]netip.Addr{"kept": propKept}
		}
	}
	h6 = base
	h6.Local = nil
	h6.Subnet6, h6.Gateway6 = mirror6P(base.Subnet), mirror6(base.Gateway)
	if base.InternalIP.IsValid() && r.Intn(4) != 0 {
		h6.InternalIPv6 = mirror6(base.InternalIP)
	}
	if base.ExternalIP.IsValid() && r.Intn(4) != 0 {
		h6.ExternalIPv6 = mirror6(base.ExternalIP)
	}
	for _, s := range base.Local {
		s.Spec = cloneSpec(s.Spec)
		if s.IP.IsValid() && r.Intn(6) != 0 {
			s.IP6 = mirror6(s.IP)
		}
		for i := range s.Spec.Services {
			for j := range s.Spec.Services[i].Ports {
				s.Spec.Services[i].Ports[j].Sources = mirrorSources(s.Spec.Services[i].Ports[j].Sources)
			}
		}
		for _, e := range s.Egress {
			m := e
			m.Prefix = mirror6P(e.Prefix)
			if e.Prefix.Bits() == 0 {
				m.Prefix = netip.MustParsePrefix("::/0")
			}
			s.Egress = append(s.Egress, m)
		}
		if s.Addrs["kept"].IsValid() { // one IP, one family: the twin is another service on another IP
			kept := s.Spec.Services[len(s.Spec.Services)-1]
			kept6 := kept
			kept6.Name, kept6.HostPort = "kept6", &v1.HostPortSource{IP: "edge6"}
			s.Spec.Services = append(s.Spec.Services, kept6)
			s.Addrs = map[string]netip.Addr{"kept": propKept, "kept6": mirror6(propKept)}
		}
		h6.Local = append(h6.Local, s)
	}
	return base, h6
}

func cloneSpec(s v1.SiloSpec) v1.SiloSpec {
	s.Ports = slices.Clone(s.Ports)
	s.Services = slices.Clone(s.Services)
	for i := range s.Services {
		s.Services[i].Ports = slices.Clone(s.Services[i].Ports)
		for j := range s.Services[i].Ports {
			s.Services[i].Ports[j].Sources = slices.Clone(s.Services[i].Ports[j].Sources)
		}
	}
	return s
}

// v4Lines is the ruleset without its IPv6 rules.
func v4Lines(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.Contains(l, "ip6 ") && !strings.Contains(l, "icmpv6 ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func siloBy6(h Host, a6 netip.Addr) (Silo, bool) {
	for _, s := range h.Local {
		if s.IP6.IsValid() && s.IP6 == a6 {
			return s, true
		}
	}
	return Silo{}, false
}

func TestPropertyNothingOverIPv6ThatIPv4WouldNotAllow(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	numbers := append(append([]int(nil), propNumbers...), 443, 8443, 30000, 9)
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		base, h := v6Cluster(r)
		text, problems := Generate(h)
		_, was := Generate(base)
		for _, p := range problems {
			if !slices.Contains(was, p) && !strings.Contains(p.Reason, "no IPv6 address on this host") {
				t.Fatalf("seed %d: the IPv6 twin made a problem: %v", seed, p)
			}
		}
		// IPv6 changes no IPv4 rule.
		if got, want := v4Lines(text), Rules(base); got != want {
			t.Fatalf("seed %d: IPv6 changed the IPv4 rules:\n%s\nwant\n%s", seed, got, want)
		}
		rs := parseNFT(t, text)
		// The IPv4 twin of a connection in is judged without the egress gate's redirect: the gate is
		// IPv4 only, so a silo hairpinning to its host's port 443 over IPv4 meets the gate first,
		// and over IPv6 the host port (which IPv4 has too).
		var noGate []string
		for _, l := range strings.Split(text, "\n") {
			if !strings.Contains(l, " redirect to ") {
				noGate = append(noGate, l)
			}
		}
		rs4 := parseNFT(t, strings.Join(noGate, "\n"))

		// In: to the host's IPv6 addresses (and anything else), from outside, the mesh, a silo.
		dsts4 := append([]netip.Addr{propInternal, propExternal, propKept, base.Gateway}, propLBs...)
		for _, s := range base.Local {
			if s.IP.IsValid() {
				dsts4 = append(dsts4, s.IP)
			}
		}
		twin := map[netip.Addr]bool{propKept: true} // the IPv4 addresses whose twin the host has
		if h.InternalIPv6.IsValid() {
			twin[propInternal] = true
		}
		if h.ExternalIPv6.IsValid() {
			twin[propExternal] = true
		}
		clients := append([]netip.Addr{v6Nowhere}, mapAddrs(propClients, mirror6)...)
		var hairpin []Silo
		for _, s := range h.Local {
			if s.IP6.IsValid() {
				hairpin = append(hairpin, s)
				break
			}
		}
		for _, iif := range []string{"eth0", MeshDevices[0], h.Bridge} {
			srcs := clients
			if iif == h.Bridge {
				srcs = mapAddrs(hairpin, func(s Silo) netip.Addr { return s.IP6 })
			}
			for _, src := range srcs {
				src4, ok := unmirror(src)
				if !ok {
					t.Fatalf("no twin for %s", src)
				}
				for _, dst4 := range dsts4 {
					dst := mirror6(dst4)
					for _, proto := range []string{"tcp", "udp"} {
						for _, port := range numbers {
							got6, ok6 := rs.reaches(t, h, pkt{iif: iif, saddr: src, daddr: dst, proto: proto, dport: port})
							got4, ok4 := rs4.reaches(t, h, pkt{iif: iif, saddr: src4, daddr: dst4, proto: proto, dport: port})
							if ok6 {
								s, local := siloBy6(h, got6.Addr())
								if !local || !ok4 || got4 != netip.AddrPortFrom(s.IP, got6.Port()) {
									t.Fatalf("seed %d: %s %s→%s:%d on %s reached %v over IPv6; its IPv4 twin %s→%s reached %v %v\n%s", seed, proto, src, dst, port, iif, got6, src4, dst4, ok4, got4, text)
								}
							}
							// The twin is there: from outside, on an address the host has in both
							// families, to a silo with an IPv6 address.
							if iif == "eth0" && ok4 && twin[dst4] {
								if s := siloByIP(h, got4.Addr()); s.IP6.IsValid() && (!ok6 || got6 != netip.AddrPortFrom(s.IP6, got4.Port())) {
									t.Fatalf("seed %d: %s %s→%s:%d reached %v over IPv4, but its IPv6 twin %s→%s reached %v %v\n%s", seed, proto, src4, dst4, port, got4, src, dst, ok6, got6, text)
								}
							}
						}
					}
				}
			}
			// Addresses with no IPv4 twin: nothing.
			for _, src := range append(srcs, a("fe80::1"), a("::1")) {
				for _, dst := range []netip.Addr{a("fe80::5054:ff:fe00:2"), a("ff02::1"), a("::1"), a("2001:db8:5::10"), a("::ffff:198.51.100.10"), a("fd00::1")} {
					for _, port := range numbers {
						if got, ok := rs.reaches(t, h, pkt{iif: iif, saddr: src, daddr: dst, proto: "tcp", dport: port}); ok {
							t.Fatalf("seed %d: %s→%s:%d on %s reached %v\n%s", seed, src, dst, port, iif, got, text)
						}
					}
				}
			}
		}

		// Out, from each silo's port: what IPv4 lets out, and nothing closed.
		closed := []netip.Addr{a("fe80::1"), a("ff02::1"), a("fd00::1"), a("fd64:6464:6464::a40:303"), a("::1"), a("::"), a("::ffff:203.0.113.4"), h.Gateway6, a("ff05::2")}
		for _, x := range []netip.Addr{h.ExternalIPv6, h.InternalIPv6} {
			if x.IsValid() {
				closed = append(closed, x)
			}
		}
		for _, s := range h.Local {
			if !s.IP6.IsValid() {
				continue
			}
			for _, proto := range []string{"tcp", "udp"} {
				for _, port := range []int{22, 53, 80, 85, 443, 8443} {
					for _, dst4 := range propOut {
						dst := mirror6(dst4)
						if dst4 == v4Nowhere {
							dst = v6Nowhere
						}
						out6, gate6 := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP6, daddr: dst, proto: proto, dport: port})
						out4, gate4 := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP, daddr: dst4, proto: proto, dport: port})
						// The gate is IPv4 only: an IPv6 connection it would have taken goes by the
						// grants alone (fewer, never more, than IPv4 with the gate).
						if gate6 || (out6 && !out4 && !gate4) || (out4 && !out6) {
							t.Fatalf("seed %d: %s %s→%s:%d out %v (gate %v); IPv4 %s→%s out %v (gate %v)\n%s", seed, s.Key, proto, dst, port, out6, gate6, s.IP, dst4, out4, gate4, text)
						}
					}
					for _, dst := range closed {
						if out, gate := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP6, daddr: dst, proto: proto, dport: port}); out || gate {
							t.Fatalf("seed %d: %s reached %s %s:%d (gate %v)\n%s", seed, s.Key, proto, dst, port, gate, text)
						}
					}
					// The host itself: nothing over IPv6 (DNS, the gate, the endpoint are IPv4).
					for _, dst := range closed {
						if rs.toHost(t, h, pkt{iif: s.Tap, ether: s.MAC, saddr: s.IP6, daddr: dst, proto: proto, dport: port}) {
							t.Fatalf("seed %d: %s reached the host at %s %s:%d\n%s", seed, s.Key, proto, dst, port, text)
						}
					}
					// No silo over IPv6: bridged, or routed back onto the bridge.
					for _, o := range h.Local {
						if o.Key == s.Key || !o.IP6.IsValid() {
							continue
						}
						p := pkt{iif: s.Tap, oif: o.Tap, ether: s.MAC, saddr: s.IP6, daddr: o.IP6, proto: proto, dport: port}
						if rs.bridged(t, p) {
							t.Fatalf("seed %d: %s bridged to %s over IPv6 :%d\n%s", seed, s.Key, o.Key, port, text)
						}
						p.oif = h.Bridge
						if out, gate := rs.outFrom(t, h, p); out || gate {
							t.Fatalf("seed %d: %s routed to %s over IPv6 :%d\n%s", seed, s.Key, o.Key, port, text)
						}
					}
				}
			}
		}

		// A port speaks only as its silo over IPv6 too: its own IPv6 address and MAC.
		var srcs []netip.Addr
		for _, s := range h.Local {
			if s.IP6.IsValid() {
				srcs = append(srcs, s.IP6)
			}
		}
		srcs = append(srcs, a("fd64:6464:6464::a40:2fa"), a("fe80::1"), a("::"), h.Gateway6, a("2001:db8::5"))
		macs := append([]string(nil), portMACs...)
		taps := []string{"kvt99"}
		for _, s := range h.Local {
			macs, taps = append(macs, s.MAC), append(taps, s.Tap)
		}
		for _, tap := range taps {
			for _, mac := range macs {
				for _, src := range srcs {
					_, got := rs.fromPort(t, pkt{iif: tap, ether: mac, saddr: src, daddr: a("2001:db8::1"), proto: "tcp", dport: 80})
					o, known := owner(h, tap)
					want := known && o.IP.IsValid() && o.IP6.IsValid() && src == o.IP6 && (o.MAC == "" || strings.EqualFold(mac, o.MAC))
					if got != want {
						t.Fatalf("seed %d: from %s as %s (mac %q): entered %v, want %v\n%s", seed, tap, src, mac, got, want, text)
					}
				}
			}
		}
	}
}

func mapAddrs[T any](in []T, f func(T) netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, x := range in {
		out = append(out, f(x))
	}
	return out
}

func siloByIP(h Host, ip netip.Addr) Silo {
	for _, s := range h.Local {
		if s.IP == ip {
			return s
		}
	}
	return Silo{}
}

// A host with no IPv6 silo subnet has no IPv6 at all: whatever IPv6 address it or its silos are
// given, every IPv6 packet falls to a drop (no silo's port from outside, the mesh or another
// silo, not the silo bridge, none of the host's silo-facing services), even with IPv6
// forwarding on.

var (
	v6Outside = []netip.Addr{a("2001:db8:1::7"), a("2001:db8:ffff::1"), a("fe80::1"), a("::1"), a("::ffff:192.0.2.7")}
	v6Dst     = []netip.Addr{a("2001:db8:5::10"), a("fe80::5054:ff:fe00:2"), a("fd00:64::2"), a("::ffff:10.64.2.2"), a("ff02::1")}
	v6Ports   = []int{22, 53, 80, 443, 5432, 6443, 8080, 15001, 30001, 30303, 51820}
)

func TestPropertyNothingOverIPv6WithoutAnIPv6Subnet(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := portCluster(r)
		// IPv6 everywhere but the silo subnet: the host's addresses, the silos', a grant.
		g.h.ExternalIPv6, g.h.InternalIPv6 = a("2001:db8:5::10"), a("2001:db8:6::10")
		for i := range g.h.Local {
			g.h.Local[i].IP6 = a("fd00:64::2")
			g.h.Local[i].Egress = append(g.h.Local[i].Egress, v1.ParsedEgress{Prefix: netip.MustParsePrefix("::/0"), Protocols: []string{"tcp", "udp"}})
		}
		text := Rules(g.h)
		if strings.Contains(text, "ip6 ") {
			t.Fatalf("seed %d: IPv6 rules without an IPv6 silo subnet:\n%s", seed, text)
		}
		rs := parseNFT(t, text)
		for _, proto := range []string{"tcp", "udp"} {
			for _, port := range v6Ports {
				for _, src := range v6Outside {
					for _, dst := range v6Dst {
						// From outside, the mesh, the bridge itself: routed onto the bridge (as if
						// IPv6 forwarding were on), it never gets through forward.
						for _, iif := range []string{"eth0", MeshDevices[0], MeshDevices[1], g.h.Bridge} {
							p := pkt{iif: iif, saddr: src, daddr: dst, proto: proto, dport: port}
							q, redirected := rs.prerouting(t, p)
							if redirected || q.dnat {
								t.Fatalf("seed %d: %s %s→%s:%d on %s was translated\n%s", seed, proto, src, dst, port, iif, text)
							}
							q.oif = g.h.Bridge
							if v := rs.verdict(t, "inet forward", q); v == "accept" {
								t.Fatalf("seed %d: %s %s→%s:%d from %s forwarded to the silo bridge\n%s", seed, proto, src, dst, port, iif, text)
							}
						}
						// To the host from the bridge (DNS, the gate, the endpoint): dropped.
						if v := rs.verdict(t, "inet input", pkt{iif: g.h.Bridge, saddr: src, daddr: dst, proto: proto, dport: port}); v == "accept" {
							t.Fatalf("seed %d: %s %s→%s:%d from the bridge accepted by the host\n%s", seed, proto, src, dst, port, text)
						}
						// From any silo's port: nothing enters the bridge, so nothing reaches anything.
						for _, s := range g.h.Local {
							p := pkt{iif: s.Tap, ether: s.MAC, saddr: src, daddr: dst, proto: proto, dport: port}
							if _, ok := rs.fromPort(t, p); ok {
								t.Fatalf("seed %d: %s sent %s %s→%s:%d onto the bridge\n%s", seed, s.Key, proto, src, dst, port, text)
							}
							if rs.toHost(t, g.h, p) {
								t.Fatalf("seed %d: %s reached the host over IPv6 at %s:%d", seed, s.Key, dst, port)
							}
							if out, gate := rs.outFrom(t, g.h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: src, daddr: dst, proto: proto, dport: port}); out || gate {
								t.Fatalf("seed %d: %s reached %s:%d over IPv6 (gate %v)", seed, s.Key, dst, port, gate)
							}
						}
					}
				}
			}
		}
	}
}

// A host whose IPv4 address on a network is IPv6 opens no host port there (that field is IPv4;
// the IPv6 address goes in ExternalIPv6), and says so; its IPv4 address on the other network
// still works.
func TestAnIPv6HostAddressInAnIPv4FieldOpensNothing(t *testing.T) {
	s := Silo{Key: "dev/web", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{}, v1.NetworkInternal, v1.NetworkExternal)}
	h := host(s)
	h.ExternalIP = a("2001:db8::10")
	text, problems := Generate(h)
	if strings.Contains(text, "2001:db8") {
		t.Fatalf("an IPv6 address in the IPv4 rules:\n%s", text)
	}
	if !strings.Contains(text, "ip daddr 10.0.0.5 tcp dport 8080 dnat ip to 10.64.2.2:8080") {
		t.Errorf("the internal IPv4 port went too:\n%s", text)
	}
	found := false
	for _, p := range problems {
		found = found || (p.Kind == "Host" && p.Owner == "externalIP")
	}
	if !found {
		t.Errorf("not reported: %+v", problems)
	}
}
