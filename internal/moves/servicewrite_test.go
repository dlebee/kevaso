package moves

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A host may write a silo back with status.service as it stood. Changing the addresses the
// control plane assigned is refused.
func TestHostWriteKeepsServiceStatus(t *testing.T) {
	old := v1.SiloStatus{Host: "hv1", Phase: "Running", Service: v1.SiloServiceStatus{
		LoadBalancerIP: "203.0.113.10", EgressIP: "203.0.113.11", HostAddresses: []string{"203.0.113.12"}}}
	round := old
	round.Phase = "Starting"
	if err := HostWrite(old, round, "hv1"); err != nil {
		t.Fatalf("writing it back: %v", err)
	}
	egress := round
	egress.Service.EgressIP = "198.51.100.9"
	if err := HostWrite(old, egress, "hv1"); err == nil {
		t.Fatal("changed egressIP")
	}
	lb := old
	lb.Service.LoadBalancerIP = "198.51.100.8"
	if err := HostWrite(old, lb, "hv1"); err == nil {
		t.Fatal("changed loadBalancerIP")
	}
	addrs := old
	addrs.Service.HostAddresses = []string{"198.51.100.7"}
	if err := HostWrite(old, addrs, "hv1"); err == nil {
		t.Fatal("changed hostAddresses")
	}
}
