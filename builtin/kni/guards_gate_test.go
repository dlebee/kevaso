package kni

import (
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func gateHost(local ...Silo) Host {
	return Host{Bridge: "kvbr0", Subnet: netip.MustParsePrefix("10.64.2.0/24"), Gateway: netip.MustParseAddr("10.64.2.1"),
		ExternalIP: netip.MustParseAddr("198.51.100.10"), Local: local, GatePort: 15001}
}

// The egress gate's port on the gateway is reachable from the bridge only while some silo's
// traffic is redirected to it. With no silo that goes through the gate, nothing listens there to
// be reached and the port stays shut like every other port of the host.
func TestTheGatePortIsOpenToSilosOnlyWhileASiloGoesThroughTheGate(t *testing.T) {
	const accept = `iifname "kvbr0" ip daddr 10.64.2.1 tcp dport 15001 accept`
	plain := Silo{Key: "dev/plain", IP: netip.MustParseAddr("10.64.2.2"), Tap: "kvt-plain"}
	if r := Rules(gateHost(plain)); strings.Contains(r, accept) || strings.Contains(r, "redirect to :15001") {
		t.Fatalf("no silo goes through the gate, but its port is open or redirected:\n%s", r)
	}
	gated := Silo{Key: "dev/gated", IP: netip.MustParseAddr("10.64.2.3"), Tap: "kvt-gated", GatePorts: []v1.PortRange{{From: 443, To: 443}}}
	r := Rules(gateHost(plain, gated))
	for _, want := range []string{accept, "redirect to :15001"} {
		if !strings.Contains(r, want) {
			t.Fatalf("a silo goes through the gate and %q is missing:\n%s", want, r)
		}
	}
}
