package kni

import (
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-002: each port on the silo bridge speaks only as the silo it was made for. From the moment
// a silo's tap (or veth) is on the bridge, a frame from it passes the bridge's prerouting hook (the
// one frames for the host itself pass too) only with that silo's own IPv4 source address, and its
// MAC where the runtime fixed one; ARP likewise. IPv6, other ether types, and any frame from a port
// whose silo has no address yet, or that the rules don't know, are dropped. Judged by sending
// frames through the generated rules, not by reading them.

var (
	portEndpoint = a("169.254.42.1")
	portStranger = []netip.Addr{a("10.64.2.250"), a("10.64.9.9"), a("0.0.0.0"), a("192.0.2.7"), a("169.254.42.1")}
	portV6       = []netip.Addr{a("fe80::1"), a("fe80::5054:ff:fe12:3456"), a("2001:db8::5"), a("::")}
	portMACs     = []string{"", "02:00:00:00:00:99", "ff:ff:ff:ff:ff:ff"}
)

func macOf(i int) string { return fmt.Sprintf("52:4b:00:00:00:%02x", i) }

// portCluster is genClusterOf with MACs (VM silos have one fixed by the runtime; container silos
// don't yet) and the local endpoint for some silos.
func portCluster(r *rand.Rand) genCluster {
	g := genClusterOf(r)
	g.h.Endpoint = portEndpoint
	g.h.GatePort = 15001
	for i := range g.h.Local {
		if r.Intn(3) != 0 {
			g.h.Local[i].MAC = macOf(i)
		}
		g.h.Local[i].Endpoint = r.Intn(2) == 0
		if r.Intn(2) == 0 {
			g.h.Local[i].GatePorts = []v1.PortRange{{From: 443, To: 443}}
		}
	}
	return g
}

// owner is the local silo a tap belongs to.
func owner(h Host, tap string) (Silo, bool) {
	for _, s := range h.Local {
		if s.Tap == tap {
			return s, true
		}
	}
	return Silo{}, false
}

// mayFrom: may a frame from tap, with this source address and MAC, enter the bridge?
func mayFrom(h Host, tap string, saddr netip.Addr, mac string) bool {
	s, ok := owner(h, tap)
	if !ok || !s.IP.IsValid() || !s.IP.Is4() || saddr != s.IP {
		return false
	}
	return s.MAC == "" || strings.EqualFold(mac, s.MAC)
}

func TestPropertyAPortSpeaksOnlyAsItsSilo(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := portCluster(r)
		text := Rules(g.h)
		rs := parseNFT(t, text)
		taps := []string{"kvt99", "kvtffffffffff"} // on the bridge, unknown to the rules
		var addrs []netip.Addr
		macs := append([]string(nil), portMACs...)
		for _, s := range g.h.Local {
			taps = append(taps, s.Tap)
			macs = append(macs, s.MAC)
		}
		for _, s := range g.h.All {
			if s.IP.IsValid() {
				addrs = append(addrs, s.IP)
			}
		}
		addrs = append(append(addrs, portStranger...), g.h.Gateway)
		for _, tap := range taps {
			for _, mac := range macs {
				for _, src := range append(append([]netip.Addr(nil), addrs...), portV6...) {
					dsts := []netip.Addr{g.h.Gateway, portEndpoint, a("10.64.2.3"), a("203.0.113.4")}
					protos := []string{"tcp", "udp", "arp"}
					if src.Is6() {
						dsts, protos = []netip.Addr{a("ff02::1"), a("fe80::1"), a("2001:db8::1")}, []string{"tcp", "udp"}
					}
					for _, proto := range protos {
						for _, dst := range dsts {
							p := pkt{iif: tap, ether: mac, saddr: src, daddr: dst, proto: proto, dport: 80}
							_, got := rs.fromPort(t, p)
							if want := mayFrom(g.h, tap, src, mac); got != want {
								t.Fatalf("seed %d: %s from %s as %s (mac %q) to %s: entered %v, want %v\n%s", seed, proto, tap, src, mac, dst, got, want, text)
							}
						}
					}
				}
			}
		}
	}
}

// The two things that tell silos apart by source address: the local endpoint (its secrets) and
// the egress gate (its injected credentials) must never take one silo for another, whatever the
// other claims, and a silo whose address isn't bound yet reaches neither.
func TestPropertyNoSiloIsTakenForAnother(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := portCluster(r)
		text := Rules(g.h)
		rs := parseNFT(t, text)
		for _, from := range g.h.Local {
			for _, as := range g.h.Local {
				if !as.IP.IsValid() {
					continue
				}
				for _, mac := range []string{from.MAC, as.MAC, ""} {
					self := from.Key == as.Key && from.IP.IsValid() && (from.MAC == "" || mac == from.MAC)
					ep := rs.toHost(t, g.h, pkt{iif: from.Tap, ether: mac, saddr: as.IP, daddr: portEndpoint, proto: "tcp", dport: 80})
					if want := self && as.Endpoint; ep != want {
						t.Fatalf("seed %d: %s as %s (mac %q) to the local endpoint: %v, want %v\n%s", seed, from.Key, as.Key, mac, ep, want, text)
					}
					_, gate := rs.outFrom(t, g.h, pkt{iif: from.Tap, oif: "eth0", ether: mac, saddr: as.IP, daddr: a("203.0.113.4"), proto: "tcp", dport: 443})
					if want := self && len(as.GatePorts) > 0; gate != want {
						t.Fatalf("seed %d: %s as %s (mac %q) to the egress gate: %v, want %v\n%s", seed, from.Key, as.Key, mac, gate, want, text)
					}
				}
			}
		}
	}
}

// The baseline a host loads at boot (no silos known yet) lets no port on the bridge say anything.
func TestABridgeWithNoSilosKnownPassesNothing(t *testing.T) {
	h := Host{Bridge: "kvbr0", Subnet: netip.MustParsePrefix("10.64.0.0/24"), Gateway: a("10.64.0.1")}
	rs := parseNFT(t, Rules(h))
	for _, p := range []pkt{
		{iif: "kvt0011223344", saddr: a("10.64.0.2"), daddr: a("10.64.0.1"), proto: "udp", dport: 53},
		{iif: "kvt0011223344", saddr: a("10.64.0.2"), daddr: a("10.64.0.3"), proto: "arp"},
		{iif: "kvt0011223344", saddr: a("fe80::1"), daddr: a("ff02::1"), proto: "udp", dport: 547},
	} {
		if _, ok := rs.fromPort(t, p); ok {
			t.Errorf("%+v entered the bridge", p)
		}
	}
}
