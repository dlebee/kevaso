package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A grant of 0.0.0.0/0 still reaches a public address, another silo, a Service and DNS.
// It does not reach a closed range, link-local, or this host's own addresses: those drops
// stand before the grant's accept.
func TestWideCIDRDoesNotReachClosedRangesOrThisHost(t *testing.T) {
	e, err := v1.EgressRule{To: "0.0.0.0/0", Ports: []string{"443"}}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	src := Silo{Key: "dev/probe", IP: a("10.64.2.2"), Tap: "kvt02", MAC: "02:00:00:00:00:02", Egress: []v1.ParsedEgress{e}}
	peer := Silo{Key: "dev/peer", IP: a("10.64.2.3"), Tap: "kvt03", MAC: "02:00:00:00:00:03",
		Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "http", Port: 8080}},
			Services: []v1.SiloService{{Ports: []v1.ServicePort{{Port: "http", AllowFrom: []string{"probe"}}}}}}}
	h := host(src, peer)
	h.All = []Silo{src, peer, {Key: "other/far", IP: a("10.64.3.9")}}
	h.Services = []Service{{Key: "dev/web", ClusterIP: a("10.65.0.1"),
		Ports: []ServicePort{{Proto: "tcp", Port: 8080, Targets: []Target{{IP: a("10.64.2.3"), Port: 8080, Local: true}}}}}}
	rs := parseNFT(t, Rules(h))

	pktFrom := func(dst string, port int) pkt {
		return pkt{iif: src.Tap, oif: "eth0", ether: src.MAC, saddr: src.IP, daddr: a(dst), proto: "tcp", dport: port}
	}
	if out, gate := rs.outFrom(t, h, pktFrom("203.0.113.9", 443)); !out || gate {
		t.Fatalf("a public address: out %v gate %v", out, gate)
	}
	for _, dst := range []string{"169.254.169.254", "127.0.0.1", "0.1.2.3", "224.0.0.1", "198.51.100.10", "10.0.0.5"} {
		if out, gate := rs.outFrom(t, h, pktFrom(dst, 443)); out || gate {
			t.Errorf("%s was forwarded (out %v gate %v)", dst, out, gate)
		}
	}
	if out, gate := rs.outFrom(t, h, pktFrom("10.64.3.9", 443)); !out || gate {
		t.Fatalf("another silo over the mesh: out %v gate %v", out, gate)
	}
	if !rs.bridged(t, pkt{iif: src.Tap, oif: peer.Tap, ether: src.MAC, saddr: src.IP, daddr: peer.IP, proto: "tcp", dport: 8080}) {
		t.Fatal("allowFrom on this host was dropped")
	}
	svc := pkt{iif: src.Tap, oif: h.Bridge, ether: src.MAC, saddr: src.IP, daddr: a("10.65.0.1"), proto: "tcp", dport: 8080}
	if out, gate := rs.outFrom(t, h, svc); !out || gate {
		t.Fatalf("a Service: out %v gate %v", out, gate)
	}
	if !rs.toHost(t, h, pkt{iif: src.Tap, ether: src.MAC, saddr: src.IP, daddr: h.Gateway, proto: "udp", dport: 53}) {
		t.Fatal("DNS to the gateway was dropped")
	}

	text := Rules(h)
	_, fwd, _ := strings.Cut(text, "chain forward {")
	fwd, _, _ = strings.Cut(fwd, "\n  }")
	silos := strings.Index(fwd, `ip daddr 10.64.0.0/16 accept`)
	drop := strings.Index(fwd, "169.254.0.0/16")
	grant := strings.Index(fwd, `ip daddr 0.0.0.0/0 tcp dport 443 accept`)
	hostDrop := strings.Index(fwd, "198.51.100.10")
	if silos < 0 || drop < 0 || grant < 0 || hostDrop < 0 || silos >= drop || drop >= grant || hostDrop >= grant {
		t.Fatalf("order silos %d closed %d host %d grant %d\n%s", silos, drop, hostDrop, grant, fwd)
	}
}
