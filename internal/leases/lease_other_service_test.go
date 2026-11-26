package leases

import (
	"slices"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A declared port may be in several services: here an Internal one first (other silos reach it on
// its silo IP) and a HostPort one that opens it from outside only on a lease. The lease counts:
// the port is leased, closed with no lease, opened by one. It was looked up in the first service
// only, so the port read as not leased: always open from outside, and kvo open refused it ("none
// of its ports is leased").
func TestLeaseOnAPortAnotherServiceAlsoOpens(t *testing.T) {
	spec := v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "api", Port: 8000}},
		Services: []v1.SiloService{
			{Name: "api", Ports: []v1.ServicePort{{Port: "api", AllowFrom: []string{"app"}}}},
			{Name: "api-public", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal},
				Ports: []v1.ServicePort{{Port: "api", As: 443, Sources: []string{"198.51.100.7/32"}, Lease: &v1.PortLease{Max: "2h"}}}},
		},
	}
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "ai", Name: "dev", UID: "u1"}, Spec: spec}
	if pl := Of(spec, "api"); pl == nil || pl.Max != "2h" {
		t.Fatalf("Of(api) = %+v: the HostPort service's lease is the port's", pl)
	}
	if got := Leased(spec); !slices.Equal(got, []string{"api"}) {
		t.Errorf("Leased = %v", got)
	}
	if err := Check(s, "api"); err != nil {
		t.Errorf("Check: %v", err)
	}
	if got := Closed(s, nil, t0); !slices.Equal(got, []string{"api"}) {
		t.Errorf("no lease yet: closed %v, want [api]", got)
	}
	out := Decide(Ask{Namespace: "ai", Silo: "dev", SiloUID: "u1", Port: "api", For: "1h", By: "ada"}, s, nil, nil, limits, alim, t0)
	if out.Err != nil || !out.Open {
		t.Fatalf("open: %+v", out)
	}
	if got := Closed(s, []*v1.Lease{out.Lease}, t0.Add(time.Minute)); len(got) != 0 {
		t.Errorf("leased: closed %v, want none", got)
	}
	if got := Closed(s, []*v1.Lease{out.Lease}, t0.Add(time.Hour)); !slices.Equal(got, []string{"api"}) {
		t.Errorf("lease ended: closed %v, want [api]", got)
	}
}
