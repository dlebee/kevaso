package worker

import (
	"net/netip"
	"slices"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/gate"
)

// K-057, K-092: the worker tells its egress gate every address of this host and its cluster, so a
// granted name pointed at one (the host's public address, another host's, a load balancer's) is
// refused like a private one, unless a grant names that address itself.
func TestTheGateKnowsTheClustersOwnAddresses(t *testing.T) {
	hosts := []*v1.Host{
		{ObjectMeta: meta.ObjectMeta{Name: "hv1"}, Spec: v1.HostSpec{ExternalIP: "198.51.100.10", InternalIP: "192.168.1.10"}},
		{ObjectMeta: meta.ObjectMeta{Name: "hv2"}, Spec: v1.HostSpec{ExternalIP: "198.51.100.20"},
			Status: v1.HostStatus{Network: v1.NetworkStatus{MeshIP: "10.63.0.2"}}},
	}
	silos := []*v1.Silo{{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web"}, Status: v1.SiloStatus{SiloIP: "10.64.0.2",
		Service: v1.SiloServiceStatus{LoadBalancerIP: "203.0.113.50", EgressIP: "203.0.113.51", HostAddresses: []string{"203.0.113.52"}}}}}
	svcs := []*v1.Service{{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api"}, Status: v1.ServiceStatus{ClusterIP: "10.65.0.3", LoadBalancerIP: "203.0.113.60"}}}
	got := ClusterAddresses([]netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("::")}, hosts, silos, svcs)
	for _, want := range []string{"2001:db8::10/128", "198.51.100.10/32", "192.168.1.10/32", "198.51.100.20/32", "10.63.0.2/32",
		"10.64.0.2/32", "203.0.113.50/32", "203.0.113.51/32", "203.0.113.52/32", "10.65.0.3/32", "203.0.113.60/32"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("%s missing from %v", want, got)
		}
	}
	if slices.Contains(got, netip.MustParsePrefix("::/128")) {
		t.Error("the unspecified address is listed")
	}
	// The ranges the gate refuses by itself hold the mesh, silos and services, whatever the view.
	for _, a := range []string{"10.63.0.9", "10.62.0.9", "10.64.3.9", "10.65.0.9", "169.254.42.1"} {
		if _, why := gate.Special(netip.MustParseAddr(a)); why == "" {
			t.Errorf("%s isn't refused by the gate itself", a)
		}
	}
}
