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
	ext := []string{v1.NetworkExternal}
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"},
		Spec: v1.SiloSpec{
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "preview", Port: 3000}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{
				{Port: "web", HostPort: ext, Sources: []string{"203.0.113.0/24"}},
				{Port: "debug", HostPort: ext, Sources: []string{"203.0.113.7"}, Lease: &v1.PortLease{}},
				{Port: "preview", HostPort: ext, Sources: []string{"203.0.113.0/24"}, Lease: &v1.PortLease{Max: "8h"}},
			}},
		},
		Status: v1.SiloStatus{Host: "hv1", SiloIP: "10.64.2.2"}}
	silos := []*v1.Silo{s}
	view := NetworkView("hv1", &v1.Host{Spec: v1.HostSpec{ExternalIP: "198.51.100.10"}}, silos, nil, nil)
	until := now.Add(time.Hour)
	open := &v1.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: leases.Name("api", "debug")},
		Spec: v1.LeaseSpec{Silo: "api", SiloUID: "u1", Port: "debug"}, Status: v1.LeaseStatus{Phase: v1.LeaseOpen, Until: &until}}

	closed := WithLeases(view, silos, nil, now)
	if ks := closed.Local[0]; !slices.Equal(ks.Leased, []string{"debug", "preview"}) || !slices.Equal(ks.Closed, []string{"debug", "preview"}) {
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
	if ks := opened.Local[0]; !slices.Equal(ks.Closed, []string{"preview"}) {
		t.Fatalf("debug open, preview not: %+v", ks)
	}
	if r := kni.Rules(opened); !strings.Contains(r, "ip saddr 203.0.113.7 tcp dport 9229 ct original ip daddr 198.51.100.10 ct status dnat accept") || strings.Contains(r, "dport 3000 dnat") {
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
