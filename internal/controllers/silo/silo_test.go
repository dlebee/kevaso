package silo_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func readyHost(name string) *v1.Host {
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name}}
	h.Spec.Address = "203.0.113.10"
	h.Spec.Components.Worker = &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "cloud-hypervisor"}}}
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue}}
	h.Status.Runtimes = map[string]v1.RuntimeStatus{"cloud-hypervisor": {State: "Ready"}}
	h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
	return h
}

func newSilo(name string) *v1.Silo {
	return &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"},
		ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev", Generation: 1},
		Spec:       v1.SiloSpec{Runtime: "cloud-hypervisor", Resources: v1.Resources{CPU: 2, Memory: "4Gi"}}}
}

// ── decide: pure, table-style ────────────────────────────────────────────────

func TestDecide(t *testing.T) {
	s := newSilo("a")
	st, changed, _, err := silo.Decide(s, []*v1.Host{readyHost("hv1")}, nil, now)
	if err != nil || !changed || st.Host != "hv1" || st.Phase != silo.PhaseScheduled || !meta.IsTrue(st.Conditions, "Scheduled") {
		t.Fatalf("schedulable: %+v changed=%v err=%v", st, changed, err)
	}

	st, changed, _, _ = silo.Decide(s, nil, nil, now)
	c := meta.FindCondition(st.Conditions, "Scheduled")
	if !changed || st.Phase != silo.PhasePending || c == nil || c.Reason != "Unschedulable" {
		t.Fatalf("no hosts: %+v", st)
	}
	// Same answer again: nothing to write.
	s.Status = st
	if _, changed, _, _ = silo.Decide(s, nil, nil, now.Add(time.Minute)); changed {
		t.Fatal("an unchanged decision reported a change (would write status in a loop)")
	}

	placed := newSilo("b")
	placed.Status.Host = "hv1"
	st, _, _, _ = silo.Decide(placed, []*v1.Host{readyHost("hv2")}, nil, now) // records its image
	if st.Host != "hv1" {
		t.Fatal("a placed silo was moved: silos are stateful, moves are never a side effect")
	}
	placed.Status = st
	if _, changed, _, _ = silo.Decide(placed, []*v1.Host{readyHost("hv2")}, nil, now); changed {
		t.Fatal("a placed silo with its image recorded still changed")
	}
	deleting := newSilo("c")
	deleting.DeletionTimestamp = &now
	if _, changed, _, _ = silo.Decide(deleting, []*v1.Host{readyHost("hv1")}, nil, now); changed {
		t.Fatal("a silo being deleted was scheduled")
	}
}

// ── the controller against a real API server ─────────────────────────────────

func lostHost(name string, since time.Time) *v1.Host {
	h := readyHost(name)
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: "HostLost", LastTransitionTime: since}}
	return h
}

// Losing a host: every policy, every moment.
func TestDecideOnHostLoss(t *testing.T) {
	onHv1 := func(policy string) *v1.Silo {
		s := newSilo("a")
		s.Spec.Availability.OnHostLoss = policy
		s.Status.Host, s.Status.Phase, s.Status.Address = "hv1", "Running", "10.64.0.2"
		s.Status.Init = []v1.StepStatus{{Name: "x", State: "Done"}}
		return s
	}
	lostAt := now.Add(-10 * time.Second)

	// Wait (and the default): stays, Unknown, says why; no retry timer.
	for _, policy := range []string{"", v1.OnHostLossWait} {
		st, changed, again, _ := silo.Decide(onHv1(policy), []*v1.Host{lostHost("hv1", lostAt), readyHost("hv2")}, nil, now)
		c := meta.FindCondition(st.Conditions, "HostLost")
		if !changed || again != 0 || st.Host != "hv1" || st.Phase != silo.PhaseUnknown || c == nil || c.Reason != "Waiting" {
			t.Fatalf("Wait %q: %+v again=%v", policy, st, again)
		}
	}
	// Recreate, too soon: still fencing; look again when it's safe.
	st, changed, again, _ := silo.Decide(onHv1(v1.OnHostLossRecreate), []*v1.Host{lostHost("hv1", lostAt), readyHost("hv2")}, nil, now)
	if c := meta.FindCondition(st.Conditions, "HostLost"); !changed || st.Host != "hv1" || again != silo.RecreateAfter-10*time.Second || c.Reason != "Fencing" {
		t.Fatalf("Recreate early: %+v again=%v", st, again)
	}
	// Recreate, after RecreateAfter: a fresh instance on another host, nothing carried over.
	st, changed, _, _ = silo.Decide(onHv1(v1.OnHostLossRecreate), []*v1.Host{lostHost("hv1", now.Add(-time.Minute)), readyHost("hv2")}, nil, now)
	if c := meta.FindCondition(st.Conditions, "HostLost"); !changed || st.Host != "hv2" || st.Phase != silo.PhaseScheduled ||
		st.Address != "" || st.Init != nil || c.Reason != "Recreated" {
		t.Fatalf("Recreate: %+v", st)
	}
	// …and if nowhere fits, it waits Pending (not back on the lost host).
	st, _, _, _ = silo.Decide(onHv1(v1.OnHostLossRecreate), []*v1.Host{lostHost("hv1", now.Add(-time.Minute))}, nil, now)
	if st.Host != "" || st.Phase != silo.PhasePending {
		t.Fatalf("Recreate with nowhere to go: %+v", st)
	}
	// The host comes back: the condition says so, and the agent takes over again.
	back := onHv1(v1.OnHostLossWait)
	back.Status.Conditions = []meta.Condition{{Type: "HostLost", Status: meta.ConditionTrue, Reason: "Waiting"}}
	st, changed, _, _ = silo.Decide(back, []*v1.Host{readyHost("hv1")}, nil, now)
	if c := meta.FindCondition(st.Conditions, "HostLost"); !changed || st.Host != "hv1" || c.Status != meta.ConditionFalse || c.Reason != "HostBack" {
		t.Fatalf("host back: %+v", st)
	}
	back.Status = st
	if _, changed, _, _ = silo.Decide(back, []*v1.Host{readyHost("hv1")}, nil, now); changed {
		t.Fatal("a recovered silo keeps changing")
	}
}

func TestControllerSchedulesAndRetriesWhenAHostArrives(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }() // stop the watches first, or Close waits for them
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")
	ctrl := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clock.Real{}}
	e := engine.New(clock.Real{})
	e.Register(ctrl, engine.Options{Workers: 2})
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	hosts.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Host", Name: k.Name}) })
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go e.Run(ctx)

	// No hosts yet: the silo waits, with the reason.
	if err := c.Create(ctx, newSilo("web")); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, c, "web", func(s *v1.Silo) bool {
		cond := meta.FindCondition(s.Status.Conditions, "Scheduled")
		return s.Status.Phase == silo.PhasePending && cond != nil && strings.Contains(cond.Message, "no hosts")
	})

	// A Ready worker appears (agent registers, then reports status): the pending silo lands on it.
	h := readyHost("hv1")
	st := h.Status
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.Status = st
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, c, "web", func(s *v1.Silo) bool { return s.Status.Host == "hv1" && s.Status.Phase == silo.PhaseScheduled })

	// The host is now half full (4 of 8Gi): one more fits, the third waits.
	_ = c.Create(ctx, newSilo("db"))
	_ = c.Create(ctx, newSilo("cache"))
	waitFor(ctx, t, c, "db", func(s *v1.Silo) bool { return s.Status.Host == "hv1" })
	waitFor(ctx, t, c, "cache", func(s *v1.Silo) bool {
		cond := meta.FindCondition(s.Status.Conditions, "Scheduled")
		return cond != nil && strings.Contains(cond.Message, "not enough")
	})
}

func waitFor(ctx context.Context, t *testing.T, c *client.Client, name string, ok func(*v1.Silo) bool) {
	t.Helper()
	for {
		var s v1.Silo
		if err := c.Get(ctx, "Silo", "dev", name, &s); err == nil && ok(&s) {
			return
		}
		select {
		case <-ctx.Done():
			var s v1.Silo
			_ = c.Get(context.Background(), "Silo", "dev", name, &s)
			t.Fatalf("silo %s never reached the expected state; last status %+v", name, s.Status)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// onHostLoss: Move (design §0.3): fenced first, like Recreate, then placed elsewhere with its data
// (its image, its volumes) instead of a fresh copy; a silo whose storage stopped being movable waits.
func TestDecideOnHostLossMove(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	moving := func() *v1.Silo {
		s := newSilo("files")
		s.Spec.Runtime = "docker"
		s.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "10Gi", MountPath: "/data"}}
		s.Spec.Availability.OnHostLoss = v1.OnHostLossMove
		s.Status.Host, s.Status.Phase, s.Status.Address = "hv1", "Running", "10.64.1.2"
		s.Status.Image = &v1.SiloImage{From: "app", Ref: "app:1", Running: "app:1"}
		s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
		return s
	}
	docker := func(h *v1.Host) *v1.Host {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		return h
	}
	s := moving()
	s.Spec.Image = "app"
	st, _, again, _ := silo.DecideIn(s, []*v1.Host{docker(lostHost("hv1", now.Add(-10*time.Second))), docker(readyHost("hv2"))}, nil, now, env)
	if c := meta.FindCondition(st.Conditions, "HostLost"); st.Host != "hv1" || c.Reason != "Fencing" || !strings.Contains(c.Message, "with its data") || again == 0 {
		t.Fatalf("Move early: %+v", st)
	}
	st, changed, _, _ := silo.DecideIn(s, []*v1.Host{docker(lostHost("hv1", now.Add(-time.Minute))), docker(readyHost("hv2"))}, nil, now, env)
	c := meta.FindCondition(st.Conditions, "HostLost")
	if !changed || st.Host != "hv2" || c.Reason != "Moved" || st.Image.Running != "app:1" || len(st.Volumes) != 1 || st.MovingFrom != "" || st.Movable != "Anywhere" {
		t.Fatalf("Move: %+v", st)
	}
	// Its class lost its topology (the plugin changed): it waits instead.
	st, _, _, _ = silo.DecideIn(moving(), []*v1.Host{docker(lostHost("hv1", now.Add(-time.Minute))), docker(readyHost("hv2"))}, nil, now, scheduler.Env{})
	if c := meta.FindCondition(st.Conditions, "HostLost"); st.Host != "hv1" || c.Reason != "Waiting" || !strings.Contains(c.Message, "can't move") {
		t.Fatalf("Move without a movable class: %+v", st)
	}
}

// The only silo in the cluster, placed by the controller: when its host is lost the controller
// still looks at it (on real machines a lone onHostLoss: Move silo stayed "Running" on a powered-off
// host forever: the controller skipped it as "placed by us, cache not caught up" once and for all).
func TestControllerSeesItsOwnPlacementsHostLost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")
	ctrl := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clock.Real{}}
	e := engine.New(clock.Real{})
	e.Register(ctrl, engine.Options{Workers: 2})
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	hosts.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Host", Name: k.Name}) })
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go e.Run(ctx)

	h := readyHost("hv1")
	st := h.Status
	_ = c.Create(ctx, h)
	h.Status = st
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, newSilo("web")); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, c, "web", func(s *v1.Silo) bool { return s.Status.Host == "hv1" })
	time.Sleep(200 * time.Millisecond) // the controller has seen its own placement come back
	var lost v1.Host
	_ = c.Get(ctx, "Host", "", "hv1", &lost)
	meta.SetCondition(&lost.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionUnknown, Reason: "HostLost", Message: "no heartbeat for 41s"}, time.Now())
	if err := c.UpdateStatus(ctx, &lost); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, c, "web", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, "HostLost")
		return c != nil && c.Status == meta.ConditionTrue
	})
}
