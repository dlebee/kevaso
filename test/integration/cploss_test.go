package integration

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// onControlPlaneLoss (design §0.7), through the API: the values and `after` are validated (on a
// silo and on a SiloSet's template), an instance carries the template's choice, and Stop on a
// cluster with exactly one system node gets a warning that says the silo stops whenever that node
// is unreachable; with a second system node, or with Continue, none.
func TestOnControlPlaneLossThroughTheAPI(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	sysNode := func(name, ip string) {
		t.Helper()
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: ip, Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}}}
		if err := c.admin.Create(c.ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	sysNode("cp-1", "10.0.0.8")
	var mu sync.Mutex
	var warnings []string
	c.admin.Warnings = func(w string) { mu.Lock(); warnings = append(warnings, w); mu.Unlock() }
	defer func() { c.admin.Warnings = nil }()
	take := func() []string {
		mu.Lock()
		defer mu.Unlock()
		w := warnings
		warnings = nil
		return w
	}
	silo := func(name string, av v1.Availability) *v1.Silo {
		s := containerSilo(name, "web3", "docker")
		s.Spec.Availability = av
		return s
	}
	refused := func(err error, want string) {
		t.Helper()
		var apiErr *client.Error
		if err == nil || !errors.As(err, &apiErr) || apiErr.Code != 422 || !strings.Contains(err.Error(), want) {
			t.Fatalf("got %v, want a 422 saying %q", err, want)
		}
	}

	// Values and after.
	refused(c.admin.Create(c.ctx, silo("bad-value", v1.Availability{OnControlPlaneLoss: "Panic"})), "onControlPlaneLoss must be Continue or Stop")
	refused(c.admin.Create(c.ctx, silo("with-continue", v1.Availability{OnControlPlaneLoss: "Continue", After: "2m"})), "goes with onControlPlaneLoss: Stop")
	refused(c.admin.Create(c.ctx, silo("with-nothing", v1.Availability{After: "2m"})), "goes with onControlPlaneLoss: Stop")
	refused(c.admin.Create(c.ctx, silo("too-soon", v1.Availability{OnControlPlaneLoss: "Stop", After: "10s"})), "want a duration from 30s")
	refused(c.admin.Create(c.ctx, silo("not-a-time", v1.Availability{OnControlPlaneLoss: "Stop", After: "soon"})), "want a duration")
	if w := take(); len(w) != 0 {
		t.Fatalf("a refused write warned: %q", w)
	}

	// Continue (also empty): fine, no warning.
	for _, av := range []v1.Availability{{}, {OnControlPlaneLoss: "Continue"}} {
		s := silo("keeps-"+strings.ToLower(av.OnControlPlaneLoss)+"x", av)
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		if stops, _ := s.StopsOnControlPlaneLoss(); stops {
			t.Fatal("Continue stops")
		}
	}
	if w := take(); len(w) != 0 {
		t.Fatalf("Continue warned: %q", w)
	}

	// Stop on one system node: warns, naming what happens.
	if err := c.admin.Create(c.ctx, silo("stops", v1.Availability{OnControlPlaneLoss: "Stop"})); err != nil {
		t.Fatal(err)
	}
	w := take()
	if len(w) != 1 || !strings.Contains(w[0], "exactly one system node") || !strings.Contains(w[0], "stop whenever that node is unreachable") {
		t.Fatalf("warnings %q", w)
	}
	var got v1.Silo
	if err := c.admin.Get(c.ctx, "Silo", "web3", "stops", &got); err != nil {
		t.Fatal(err)
	}
	if stops, after := got.StopsOnControlPlaneLoss(); !stops || after != v1.DefaultStopAfter {
		t.Fatalf("stored silo: stops=%v after=%v, want true, 2m", stops, after)
	}

	// A SiloSet's template carries it, and an instance has it.
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "web3"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: containerSilo("t", "web3", "docker").Spec}}}
	set.Spec.Template.Availability = v1.Availability{OnControlPlaneLoss: "Stop", After: "10s"}
	refused(c.admin.Create(c.ctx, set), "want a duration from 30s")
	set.Spec.Template.Availability.After = "45s"
	if err := c.admin.Create(c.ctx, set); err != nil {
		t.Fatal(err)
	}
	if w := take(); len(w) != 1 || !strings.Contains(w[0], "SiloSet pool") {
		t.Fatalf("SiloSet warnings %q", w)
	}
	if stops, after := set.Instance(0, false).StopsOnControlPlaneLoss(); !stops || after.Seconds() != 45 {
		t.Fatalf("instance: stops=%v after=%v", stops, after)
	}

	// A second system node: no more warning.
	sysNode("cp-2", "10.0.0.9")
	if err := c.admin.Create(c.ctx, silo("stops-with-two", v1.Availability{OnControlPlaneLoss: "Stop", After: "1m"})); err != nil {
		t.Fatal(err)
	}
	if w := take(); len(w) != 0 {
		t.Fatalf("warned with two system nodes: %q", w)
	}
}
