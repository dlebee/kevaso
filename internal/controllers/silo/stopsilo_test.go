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
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
)

// The host and silo controllers together, on a fake clock, with the host's agent clock an hour
// behind (audit K-014: before, the host was lost at once and a copy started 30s later while the
// old one could still run). An onControlPlaneLoss: Stop silo is started elsewhere exactly after
// its `after` plus StopMargin of silence by the control plane's own count, and not a tick before.
func TestAStopSiloRestartsAfterOurOwnCountWhateverTheAgentsClockSays(t *testing.T) {
	// Every reconcile of both controllers is driven here, in order: run as two engines, the
	// silo's first placement raced the host controller calling hv1 lost (its stamp is an hour
	// behind on purpose), and on a loaded machine the waits ran out. The only waits now are for
	// the caches to show the test's own writes.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	srv, _ := apiserver.New(store.NewMemory(0), clk)
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")
	contacts := hostctl.NewContacts(clk.Now())
	sc := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clk, Contacts: contacts}
	hc := &hostctl.Controller{Client: c, Hosts: hosts, Clock: clk, Lease: 40 * time.Second, Contacts: contacts}
	go silos.Run(ctx)
	go hosts.Run(ctx)
	if !silos.WaitSynced(ctx) || !hosts.WaitSynced(ctx) {
		t.Fatal("caches never synced")
	}
	var got v1.Silo
	// The cache has the silo as last written (its resourceVersion), then each controller looks.
	current := func() {
		t.Helper()
		if err := c.Get(ctx, "Silo", "dev", "validator", &got); err != nil {
			t.Fatal(err)
		}
		rv := got.ResourceVersion
		cacheShows(ctx, t, silos, "dev", "validator", func(o any) bool { return o.(*v1.Silo).ResourceVersion == rv })
	}
	hostSeen := func(name string) {
		t.Helper()
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			t.Fatal(err)
		}
		rv := h.ResourceVersion
		cacheShows(ctx, t, hosts, "", name, func(o any) bool { return o.(*v1.Host).ResourceVersion == rv })
	}
	// reconcileHost runs the host controller on a host until it writes nothing more (its first
	// look gives the host its mesh index; the next ones judge its lease), as the engine would.
	reconcileHost := func(name string) {
		t.Helper()
		for range 5 {
			hostSeen(name)
			var before v1.Host
			_ = c.Get(ctx, "Host", "", name, &before)
			if _, err := hc.Reconcile(ctx, engine.Key{Kind: "Host", Name: name}); err != nil {
				t.Fatal(err)
			}
			var after v1.Host
			_ = c.Get(ctx, "Host", "", name, &after)
			if after.ResourceVersion == before.ResourceVersion {
				hostSeen(name)
				return
			}
		}
		t.Fatalf("the host controller kept writing %s", name)
	}
	reconcileSilo := func() *v1.Silo {
		t.Helper()
		current()
		if _, err := sc.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "validator"}); err != nil {
			t.Fatal(err)
		}
		current()
		return &got
	}
	unreachable := func(s *v1.Silo) *meta.Condition {
		return meta.FindCondition(s.Status.Conditions, silo.CondHostUnreachable)
	}

	beat := func(name string, stamp time.Time) { // the host's agent: retried on a conflict with the host controller
		t.Helper()
		for {
			var h v1.Host
			if err := c.Get(ctx, "Host", "", name, &h); err != nil {
				h = *readyHost(name)
				st := h.Status
				if err := c.Create(ctx, &h); err != nil {
					t.Fatal(err)
				}
				h.Status = st
			} else {
				h.Status.Conditions = readyHost(name).Status.Conditions
			}
			h.Status.LastHeartbeat = &stamp
			err := c.UpdateStatus(ctx, &h)
			if err == nil {
				return
			}
			if !client.IsConflict(err) {
				t.Fatal(err)
			}
		}
	}
	behind := -time.Hour // hv1's clock
	beat("hv1", t0.Add(behind))
	hostSeen("hv1")
	s := newSilo("validator")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop // after: 2m
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s := reconcileSilo(); s.Status.Host != "hv1" {
		t.Fatalf("not placed on hv1: %+v", s.Status)
	}
	// hv1's agent arms its fence for this spec (the host lane's half).
	retry(t, func() error {
		_ = c.Get(ctx, "Silo", "dev", "validator", &got)
		meta.SetCondition(&got.Status.Conditions, fence.ArmedCondition("hv1", 2*time.Minute, got.Generation), clk.Now())
		// …and reports, once its fence has stopped it, that it did (FenceStopped).
		meta.SetCondition(&got.Status.Conditions, stoppedBy(&got, "hv1"), clk.Now())
		return c.UpdateStatus(ctx, &got)
	})
	beat("hv2", t0)
	reconcileHost("hv2")
	// hv1's stamp is an hour old by our clock: the lease calls it lost now. Its silo waits.
	reconcileHost("hv1")
	if s := reconcileSilo(); s.Status.Host != "hv1" || unreachable(s) == nil || unreachable(s).Status != meta.ConditionTrue || !strings.Contains(unreachable(s).Message, "2m16s") {
		t.Fatalf("hv1 lost: %+v", s.Status)
	}

	wait := 2*time.Minute + silo.StopMargin(2*time.Minute)
	clk.Step(wait - time.Second)
	beat("hv2", t0.Add(wait-time.Second))
	reconcileHost("hv2")
	// One second short: still there.
	if s := reconcileSilo(); s.Status.Host != "hv1" || unreachable(s) == nil || !strings.Contains(unreachable(s).Message, "2m15s so far") {
		t.Fatalf("one second short: %+v", s.Status)
	}
	clk.Step(time.Second)
	if s := reconcileSilo(); s.Status.Host != "hv2" || unreachable(s) == nil || unreachable(s).Reason != "RestartedElsewhere" {
		t.Fatalf("at our own count: %+v", s.Status)
	}
}

// retry runs a read-modify-write until it isn't refused for a conflict with a controller.
func retry(t *testing.T, write func() error) {
	t.Helper()
	for {
		err := write()
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
}
