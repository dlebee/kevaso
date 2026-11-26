package ingress_test

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ingress"
)

// K-061, the Ingress half (ingress lane; the Service half is the service controller's, in the
// control lane): an Ingress publishes outside, so its backend may only be a port the silo opens
// itself and not only on a lease. Backend takes any port the silo's own service lists, a leased
// one included, so an Ingress route to a port that opens only on an approved lease is served
// whatever the lease says.
//
// The fix (internal/ingress/desired.go, Backend and Targets): for a silo's own service, refuse a
// port whose spec.service.ports entry has lease: (ok false; and say so where the Ingress's held
// reasons are written, naming the port: "port debug of silo api opens outside only on a lease:
// an Ingress can't publish it"). For a standalone Service, route only to the silos and ports its
// status lists as endpoints, and only when the target port is one the silo opens without a lease
// (as the service controller now holds a LoadBalancer Service's endpoints: service.unpublished).
func TestK061AnIngressNeverPublishesALeasedPort(t *testing.T) {
	t.Skip("K-061, ingress lane: Backend serves a port that opens only on a lease (fix described above)")
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "shop"},
		Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "debug", Port: 9229}},
			Services: []v1.SiloService{{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "debug", Lease: &v1.PortLease{}}}}}},
		Status: v1.SiloStatus{Host: "w1", SiloIP: "10.64.1.2", Phase: "Running"}}
	if b, ok := ingress.Backend([]*v1.Silo{s}, nil, "shop", v1.IngressTarget{Name: "api", Port: "debug"}, nil); ok {
		t.Fatalf("an Ingress backend on a port that opens only on a lease: %+v", b)
	}
}
