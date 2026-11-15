package silo_test

import (
	"context"
	"net/http/httptest"
	"slices"
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
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func readyHost(name string) *v1.Host {
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name}}
	h.Spec.ExternalIP = "203.0.113.10"
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

// Losing a host: every policy stays where it is, Unknown, with HostUnreachable saying since when
// and what to do (brainstorm §0.7; the full table is TestHostLossTruthTable); no retry timer.
func TestDecideOnHostLoss(t *testing.T) {
	onHv1 := func(policy string) *v1.Silo {
		s := newSilo("a")
		s.Spec.Availability.OnHostLoss = policy
		s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.0.2"
		s.Status.Init = []v1.StepStatus{{Name: "x", State: "Done"}}
		return s
	}
	lostAt := now.Add(-time.Hour)
	for _, policy := range []string{"", v1.OnHostLossWait, v1.OnHostLossRecreate} {
		st, changed, again, _ := silo.Decide(onHv1(policy), []*v1.Host{lostHost("hv1", lostAt), readyHost("hv2")}, nil, now)
		c := meta.FindCondition(st.Conditions, "HostUnreachable")
		if !changed || again != 0 || st.Host != "hv1" || st.SiloIP == "" || st.Init == nil || st.Phase != silo.PhaseUnknown || c == nil || c.Reason != "Waiting" ||
			!strings.Contains(c.Message, lostAt.Format(time.RFC3339)) {
			t.Fatalf("%q: %+v again=%v", policy, st, again)
		}
	}
	// The host comes back: the condition says so, and the agent takes over again.
	back := onHv1(v1.OnHostLossWait)
	back.Status.Conditions = []meta.Condition{{Type: "HostUnreachable", Status: meta.ConditionTrue, Reason: "Waiting"}}
	st, changed, _, _ := silo.Decide(back, []*v1.Host{readyHost("hv1")}, nil, now)
	if c := meta.FindCondition(st.Conditions, "HostUnreachable"); !changed || st.Host != "hv1" || c.Status != meta.ConditionFalse || c.Reason != "HostBack" {
		t.Fatalf("host back: %+v", st)
	}
	back.Status = st
	if _, changed, _, _ = silo.Decide(back, []*v1.Host{readyHost("hv1")}, nil, now); changed {
		t.Fatal("a recovered silo keeps changing")
	}
}

func TestControllerSchedulesAndRetriesWhenAHostArrives(t *testing.T) {
	// Every reconcile is driven here, in order (an engine with two workers placed db or cache
	// first, as it happened: the test then waited out its 20 s under load). The only waits are
	// for the cache to show the test's own writes.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }() // stop the watches first, or Close waits for them
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")
	ctrl := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clock.Real{}}
	go silos.Run(ctx)
	go hosts.Run(ctx)
	if !silos.WaitSynced(ctx) || !hosts.WaitSynced(ctx) {
		t.Fatal("caches never synced")
	}
	reconcile := func(name string) *v1.Silo {
		t.Helper()
		cacheShows(ctx, t, silos, "dev", name, func(any) bool { return true })
		if _, err := ctrl.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: name}); err != nil {
			t.Fatal(err)
		}
		var s v1.Silo
		if err := c.Get(ctx, "Silo", "dev", name, &s); err != nil {
			t.Fatal(err)
		}
		return &s
	}
	scheduled := func(s *v1.Silo) string {
		if cond := meta.FindCondition(s.Status.Conditions, "Scheduled"); cond != nil {
			return cond.Message
		}
		return ""
	}

	// No hosts yet: the silo waits, with the reason.
	if err := c.Create(ctx, newSilo("web")); err != nil {
		t.Fatal(err)
	}
	if s := reconcile("web"); s.Status.Phase != silo.PhasePending || !strings.Contains(scheduled(s), "no hosts") {
		t.Fatalf("no hosts: %+v", s.Status)
	}

	// A Ready worker appears (agent registers, then reports status): a host's change looks at the
	// pending silos again (Map), and the pending silo lands on it.
	h := readyHost("hv1")
	st := h.Status
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.Status = st
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	cacheShows(ctx, t, hosts, "", "hv1", func(o any) bool { return meta.IsTrue(o.(*v1.Host).Status.Conditions, "Ready") })
	cacheShows(ctx, t, silos, "dev", "web", func(o any) bool { return o.(*v1.Silo).Status.Phase == silo.PhasePending })
	if keys := ctrl.Map(engine.Key{Kind: "Host", Name: "hv1"}); !slices.Contains(keys, engine.Key{Kind: "Silo", Namespace: "dev", Name: "web"}) {
		t.Fatalf("a host arriving doesn't look at the pending silo again: %v", keys)
	}
	if s := reconcile("web"); s.Status.Host != "hv1" || s.Status.Phase != silo.PhaseScheduled {
		t.Fatalf("not placed when the host arrived: %+v", s.Status)
	}

	// The host is now half full (2 of 4 CPUs, 4 of 8Gi): one more fits, the third waits.
	_ = c.Create(ctx, newSilo("db"))
	_ = c.Create(ctx, newSilo("cache"))
	if s := reconcile("db"); s.Status.Host != "hv1" {
		t.Fatalf("db: %+v", s.Status)
	}
	if s := reconcile("cache"); s.Status.Host != "" || !strings.Contains(scheduled(s), "not enough") {
		t.Fatalf("cache, with hv1 full: %+v", s.Status)
	}
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

// onHostLoss: Move whose storage stopped being movable: the condition says it can't move.
func TestDecideOnHostLossMove(t *testing.T) {
	s := newSilo("files")
	s.Spec.Runtime = "docker"
	s.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "10Gi", MountPath: "/data"}}
	s.Spec.Availability.OnHostLoss = v1.OnHostLossMove
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	st, _, _, _ := silo.DecideIn(s, []*v1.Host{lostHost("hv1", now.Add(-time.Minute)), readyHost("hv2")}, nil, now, scheduler.Env{})
	if c := meta.FindCondition(st.Conditions, "HostUnreachable"); st.Host != "hv1" || c.Reason != "Waiting" || !strings.Contains(c.Message, "can't move") {
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
		c := meta.FindCondition(s.Status.Conditions, "HostUnreachable")
		return c != nil && c.Status == meta.ConditionTrue
	})
}

// K-005: a handoff in progress (hv1 still has to let go) when the destination hv2 is lost. Moving
// on to hv3 must keep the record that hv1 has not let go: hv3 may not start the silo until it has,
// or two copies run on the same data. Recreate keeps it the same way.
func TestK005LosingTheDestinationKeepsTheHandoff(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	docker := func(h *v1.Host) *v1.Host {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		return h
	}
	for _, policy := range []string{v1.OnHostLossMove, v1.OnHostLossRecreate} {
		s := newSilo("files")
		s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
		s.Spec.Availability.OnHostLoss = policy
		if policy == v1.OnHostLossMove {
			s.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "10Gi", MountPath: "/data"}}
			s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
		}
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv2", "hv1", "Scheduled"
		s.Status.Image = &v1.SiloImage{From: "app", Ref: "app:1", Running: "app:1"}
		hv1 := docker(readyHost("hv1"))
		hv1.Spec.Unschedulable = true // being drained
		hosts := []*v1.Host{hv1, docker(lostHost("hv2", now.Add(-time.Minute))), docker(readyHost("hv3"))}
		st, changed, _, err := silo.DecideIn(s, hosts, nil, now, env)
		if err != nil || !changed || st.Host != "hv3" {
			t.Fatalf("%s: not placed on hv3: %v %+v", policy, err, st)
		}
		next := *s
		next.Status = st
		if st.MovingFrom != "hv1" || moves.MayStart(&next, "hv3") {
			t.Fatalf("%s: hv3 may start it while hv1 has not let go (movingFrom %q)", policy, st.MovingFrom)
		}
	}
}
