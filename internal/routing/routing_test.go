package routing_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/routing"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func silo(routeWhen string, readinessProbe bool, phase string, ready bool) *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "rpc-0", Namespace: "web3", Labels: map[string]string{"app": "rpc"}},
		Spec:   v1.SiloSpec{Service: &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8545}}, RouteWhen: routeWhen}},
		Status: v1.SiloStatus{Phase: phase, Address: "10.64.1.2", Host: "w1"}}
	if readinessProbe {
		s.Spec.Probes = &v1.Probes{Readiness: &v1.Probe{HTTP: &v1.HTTPProbe{Port: "rpc"}}}
	}
	st, reason, msg := meta.ConditionFalse, "NotReady", "readiness failing: HTTP 503"
	if ready {
		st, reason, msg = meta.ConditionTrue, "ReadinessPassing", "running, readiness passing"
	}
	meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: st, Reason: reason, Message: msg}, t0)
	return s
}

func TestSilo(t *testing.T) {
	for _, tc := range []struct {
		name   string
		s      *v1.Silo
		routed bool
		mode   string
		stated bool
		reason string
	}{
		{"no probe, nothing stated: running, and it says so", silo("", false, "Running", true), true, "running", false, ""},
		{"ready and ready: routed", silo("ready", true, "Running", true), true, "ready", true, ""},
		{"ready and not ready: held, with why", silo("ready", true, "Running", false), false, "ready", true, "not ready: readiness failing: HTTP 503"},
		{"running: routed whatever readiness says", silo("running", true, "Running", false), true, "running", true, ""},
		{"not running: held whatever it says", silo("running", false, "Starting", true), false, "running", true, "not running (Starting)"},
		{"probe and nothing stated: held", silo("", true, "Running", true), false, "", false, "isn't stated"},
		{"ready without a probe: held", silo("ready", false, "Running", true), false, "ready", true, "no readiness probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := routing.Silo(tc.s.Spec, tc.s.Status)
			if r.Routed != tc.routed || r.RouteWhen != tc.mode || r.Stated != tc.stated || !strings.Contains(r.Reason, tc.reason) || (tc.routed && r.Reason != "") {
				t.Fatalf("%+v", r)
			}
			if !tc.routed && strings.HasPrefix(tc.reason, "not ") && (r.Since == nil || !r.Since.Equal(t0)) {
				t.Fatalf("held since %v, want the Ready condition's transition", r.Since)
			}
			if routing.Routed(tc.s) != tc.routed {
				t.Fatal("Routed disagrees")
			}
		})
	}
	if routing.Silo(v1.SiloSpec{}, v1.SiloStatus{}) != nil || !routing.Routed(&v1.Silo{}) {
		t.Fatal("no service: nothing to route, nothing held")
	}
	noAddr := silo("running", false, "Running", true)
	noAddr.Status.Address = ""
	if routing.Routed(noAddr) {
		t.Fatal("no address: nothing to send to")
	}
}

// A Service's routeWhen decides for its endpoints, not the silo's own service.
func TestEndpoint(t *testing.T) {
	svc := func(rw string) *v1.Service {
		return &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"}, Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, RouteWhen: rw}}
	}
	s := silo("running", true, "Running", false)
	if r := routing.Endpoint(svc("ready"), s); r.Routed || !strings.Contains(r.Reason, "HTTP 503") {
		t.Fatalf("ready service, not ready silo: %+v", r)
	}
	if r := routing.Endpoint(svc("running"), s); !r.Routed {
		t.Fatalf("running service: %+v", r)
	}
	if r := routing.Endpoint(svc(""), s); r.Routed || !strings.Contains(r.Reason, "isn't stated") {
		t.Fatalf("service states nothing, silo has a probe: %+v", r)
	}
	if r := routing.Endpoint(svc("ready"), silo("", false, "Running", true)); r.Routed || !strings.Contains(r.Reason, "no readiness probe") {
		t.Fatalf("ready service, silo with no probe: %+v", r)
	}
}

func TestCheckService(t *testing.T) {
	probed := silo("ready", true, "Running", true)
	plain := silo("", false, "Running", true)
	plain.Name = "plain"
	other := silo("", false, "Running", true)
	other.Name, other.Labels = "db", map[string]string{"app": "db"}
	set := &v1.SiloSet{ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "web3"}, Spec: v1.SiloSetSpec{Template: v1.SiloTemplate{
		Labels: map[string]string{"app": "rpc"}, SiloSpec: probed.Spec}}}
	instance := silo("ready", true, "Running", true)
	instance.Labels = map[string]string{"app": "rpc", v1.LabelSiloSet: "pool"}
	svc := func(rw string, sel string) *v1.Service {
		return &v1.Service{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"}, Spec: v1.ServiceSpec{Selector: map[string]string{"app": sel}, RouteWhen: rw}}
	}
	for _, tc := range []struct {
		name  string
		svc   *v1.Service
		silos []*v1.Silo
		sets  []*v1.SiloSet
		want  []string
	}{
		{"ready over probed silos", svc("ready", "rpc"), []*v1.Silo{probed}, nil, nil},
		{"ready over a silo without a probe", svc("ready", "rpc"), []*v1.Silo{probed, plain}, nil, []string{"silo plain", "no readiness probe"}},
		{"nothing stated over a probed silo", svc("", "rpc"), []*v1.Silo{probed}, nil, []string{"silo rpc-0", "isn't stated"}},
		{"nothing stated over plain silos: running", svc("", "db"), []*v1.Silo{probed, other}, nil, nil},
		{"running over anything", svc("running", "rpc"), []*v1.Silo{probed, plain}, nil, nil},
		{"a set's template counts before its instances exist", svc("", "rpc"), nil, []*v1.SiloSet{set}, []string{"SiloSet pool"}},
		{"instances are checked as their set", svc("", "rpc"), []*v1.Silo{instance}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := strings.Join(routing.CheckService(tc.svc, tc.silos, tc.sets), "; ")
			if len(tc.want) == 0 && errs != "" {
				t.Fatalf("refused: %s", errs)
			}
			for _, w := range tc.want {
				if !strings.Contains(errs, w) {
					t.Fatalf("%q doesn't say %q", errs, w)
				}
			}
		})
	}
}
