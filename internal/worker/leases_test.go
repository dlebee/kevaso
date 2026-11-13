package worker

import (
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/leases"
)

func TestWithLeases(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"},
		Spec: v1.SiloSpec{Service: &v1.SiloService{
			Ports:    []v1.ServicePort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}},
			Expose:   v1.ExposeHostPort,
			HostPort: &v1.HostPortSpec{AllowFrom: []string{"203.0.113.0/24"}},
			Lease:    &v1.ServiceLease{Ports: []string{"debug"}, AllowFrom: []string{"203.0.113.7", "198.51.100.0/24"}},
		}},
		Status: v1.SiloStatus{Host: "hv1", Address: "10.64.2.2", Service: v1.SiloServiceStatus{PublicIP: "198.51.100.10"}}}
	silos := []*v1.Silo{s}
	view := NetworkView("hv1", nil, silos, nil)
	until := now.Add(time.Hour)
	open := &v1.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: leases.Name("api", "debug")},
		Spec: v1.LeaseSpec{Silo: "api", SiloUID: "u1", Port: "debug"}, Status: v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &until}}

	closed := WithLeases(view, silos, nil, now)
	if ks := closed.Local[0]; !slices.Equal(ks.Leased, []string{"debug"}) || !slices.Equal(ks.Closed, []string{"debug"}) || !slices.Equal(ks.LeaseFrom, []string{"203.0.113.7"}) {
		t.Fatalf("no lease: %+v", ks)
	}
	if len(view.Local[0].Closed) != 0 {
		t.Fatal("the view given was changed")
	}
	closedRules := kni.Rules(closed)
	if strings.Contains(closedRules, "dport 9229 dnat") || !strings.Contains(closedRules, "dport 8080 dnat") {
		t.Fatalf("closed rules:\n%s", closedRules)
	}
	opened := WithLeases(view, silos, []*v1.Lease{open}, now)
	if ks := opened.Local[0]; len(ks.Closed) != 0 {
		t.Fatalf("open: %+v", ks)
	}
	if r := kni.Rules(opened); !strings.Contains(r, "ip saddr 203.0.113.7 tcp dport 9229 ct status dnat accept") {
		t.Fatalf("open rules:\n%s", r)
	}
	// At its end, the same inputs give the closed rules again.
	if kni.Rules(WithLeases(view, silos, []*v1.Lease{open}, until)) != closedRules {
		t.Fatal("rules at the lease's end aren't the closed ones")
	}
	// The host wakes at the end.
	ch, stop := leaseTimer([]*v1.Lease{open}, now)
	defer stop()
	if ch == nil {
		t.Fatal("no timer for an open lease")
	}
	if ch, _ := leaseTimer(nil, now); ch != nil {
		t.Fatal("a timer without leases")
	}
}
