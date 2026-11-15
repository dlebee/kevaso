package agent_test

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// K-002, the local endpoint's half (host lane). The endpoint takes a caller for the silo
// registered at its source address (BySource). The bridge now drops, per port, any source but
// that port's own silo's (builtin/kni), so the address is the port, but only while that ruleset
// is loaded: before the first one (a boot, kevasod starting) and with a stale registration, the
// address alone is all the endpoint goes by. Fix: the agent gets a `Bound func(netip.Addr)
// (tap string, ok bool)` from the worker (the worker's loadedBindings, as the egress gate uses
// in internal/worker/egress.go `local`), and BySource answers only when the address is bound to
// the registered silo's own tap (cloudhypervisor.NamesFor(id).Tap). Then change this test to
// give the Endpoint a Bound that knows nothing, and keep the assertion.
func TestTheEndpointKnowsNoSiloByAnAddressNoPortIsBoundTo(t *testing.T) {
	t.Skip("K-002 host-lane half: Endpoint.BySource trusts the source address alone (see the comment)")
	e := &agent.Endpoint{}
	addr := netip.MustParseAddr("10.64.0.7")
	e.Register(addr, kri.ID{Namespace: "dev", Name: "a", UID: "u-a"})
	r := httptest.NewRequest("GET", "/v1/secrets/x", nil)
	r.RemoteAddr = "10.64.0.7:40000"
	if id, ok := e.BySource(r); ok {
		t.Fatalf("taken for %s by its address alone, with no ruleset binding it to a port", id.Name)
	}
}
