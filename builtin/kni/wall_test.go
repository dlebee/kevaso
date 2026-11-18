package kni

import (
	"net/netip"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A silo on one host reaches another host's silos, and not that host's own address, nor anything
// the other host listens on that arrives over the mesh. DNS to its own gateway stays.
func TestASiloDoesNotReachAnotherHostsOwnAddress(t *testing.T) {
	local := Silo{Key: "ns/a", IP: a("10.64.2.5"), Spec: v1.SiloSpec{}}
	ra := parseNFT(t, Rules(host(local)))
	for _, port := range []int{6443, 22, 51820} {
		for _, proto := range []string{"tcp", "udp"} {
			p := pkt{iif: "kvbr0", oif: "kevaso0", saddr: a("10.64.2.5"), daddr: a("10.64.3.1"), proto: proto, dport: port}
			if got := ra.verdict(t, "inet forward", p); got != "drop" {
				t.Errorf("forward %s/%d to 10.64.3.1: %s, want drop", proto, port, got)
			}
		}
	}
	p := pkt{iif: "kvbr0", oif: "kevaso0", saddr: a("10.64.2.5"), daddr: a("10.64.3.5"), proto: "tcp", dport: 8080}
	if got := ra.verdict(t, "inet forward", p); got != "accept" {
		t.Errorf("silo to silo 10.64.3.5: %s, want accept", got)
	}
	dns := pkt{iif: "kvbr0", saddr: a("10.64.2.5"), daddr: a("10.64.2.1"), proto: "udp", dport: 53}
	if got := ra.verdict(t, "inet input", dns); got != "accept" {
		t.Errorf("a silo's DNS to its own gateway: %s, want accept", got)
	}

	b := host()
	b.Subnet = netip.MustParsePrefix("10.64.3.0/24")
	b.Gateway = a("10.64.3.1")
	rb := parseNFT(t, Rules(b))
	for _, port := range []int{6443, 22, 51820} {
		in := pkt{iif: "kevaso0", saddr: a("10.64.2.5"), daddr: a("10.64.3.1"), proto: "tcp", dport: port}
		if got := rb.verdict(t, "inet input", in); got != "drop" {
			t.Errorf("input from the mesh to port %d: %s, want drop", port, got)
		}
	}
}
