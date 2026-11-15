package kni

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// IPv6 (re-checked for the audit): Kevaso's model is IPv4, so on a host with a global IPv6 address
// nothing it closes may be reachable over IPv6: no silo's port (from outside, the mesh or another
// silo), not the silo bridge, and none of the host's silo-facing services (DNS on the gateway,
// the egress gate, the local endpoint). The rules match IPv4 explicitly where they open
// something; this checks that every IPv6 packet falls to a drop, even with IPv6 forwarding on.

var (
	v6Outside = []netip.Addr{a("2001:db8:1::7"), a("2001:db8:ffff::1"), a("fe80::1"), a("::1"), a("::ffff:192.0.2.7")}
	v6Dst     = []netip.Addr{a("2001:db8:5::10"), a("fe80::5054:ff:fe00:2"), a("fd00:64::2"), a("::ffff:10.64.2.2"), a("ff02::1")}
	v6Ports   = []int{22, 53, 80, 443, 5432, 6443, 8080, 15001, 30001, 30303, 51820}
)

func TestPropertyNothingOverIPv6(t *testing.T) {
	runs := propRuns
	if testing.Short() {
		runs = 50
	}
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		g := portCluster(r)
		text := Rules(g.h)
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

// A host whose address on a network is IPv6 opens no host port there (the rules can't take it),
// and says so; its IPv4 address on the other network still works.
func TestAnIPv6HostAddressOpensNothing(t *testing.T) {
	s := Silo{Key: "dev/web", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{HostPort: []string{v1.NetworkInternal, v1.NetworkExternal}})}
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
