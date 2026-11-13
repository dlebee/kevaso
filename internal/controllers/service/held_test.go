package service_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/service"
)

// routeWhen decides routed and held; held ones are listed apart with why and since when, and
// never among the endpoints every path sends to.
func TestSplit(t *testing.T) {
	t0 := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	mk := func(name string, probe, ready bool) *v1.Silo {
		s := silo(name, "w1", "10.64.1."+name, map[string]string{"app": "rpc"}, true)
		s.Status.SiloIP = "10.64.1." + map[string]string{"a": "2", "b": "3", "c": "4"}[name]
		if probe {
			s.Spec.Probes = &v1.Probes{Readiness: &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}}}
		}
		if !ready {
			s.Status.Conditions = nil
			meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionFalse, Message: "readiness failing: connection refused"}, t0)
		}
		return s
	}
	silos := []*v1.Silo{mk("a", true, true), mk("b", true, false), mk("c", false, true)}
	svc := func(rw string) *v1.Service {
		return &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, RouteWhen: rw, Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545}}}}
	}
	names := func(eps []v1.ServiceEndpoint) string {
		var n []string
		for _, e := range eps {
			n = append(n, e.Silo)
		}
		return strings.Join(n, ",")
	}
	for _, tc := range []struct {
		rw, routed, held, why string
	}{
		{"ready", "a", "b,c", "connection refused"},
		{"running", "a,b,c", "", ""},
		{"", "c", "a,b", "isn't stated"},
	} {
		routed, held := service.Split(svc(tc.rw), silos)
		if names(routed) != tc.routed || names(held) != tc.held {
			t.Fatalf("routeWhen %q: routed %s held %s", tc.rw, names(routed), names(held))
		}
		if len(held) > 0 && !strings.Contains(held[0].Reason+held[len(held)-1].Reason, tc.why) {
			t.Fatalf("routeWhen %q: why %+v", tc.rw, held)
		}
	}
	_, held := service.Split(svc("ready"), silos)
	if held[0].Since == nil || !held[0].Since.Equal(t0) || !strings.Contains(held[1].Reason, "no readiness probe") {
		t.Fatalf("held: %+v", held)
	}
}
