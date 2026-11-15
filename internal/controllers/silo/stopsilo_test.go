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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	srv, _ := apiserver.New(store.NewMemory(0), clk)
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})

	silos, hosts := informer.New(c, "Silo"), informer.New(c, "Host")
	contacts := hostctl.NewContacts(clk.Now())
	e := engine.New(clk)
	e.Register(&silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clk, Contacts: contacts}, engine.Options{Workers: 1})
	e.WaitFor(silos, hosts)
	// The host controller runs in its own engine, started only once the silo is on hv1: hv1's
	// stamp is an hour behind, so the host controller calls hv1 lost as soon as it looks at it,
	// and had it looked before the silo was placed, the silo could never be placed at all (the
	// test then waited out its 20 s). The silo's placement isn't what is tested here.
	eh := engine.New(clk)
	eh.Register(&hostctl.Controller{Client: c, Hosts: hosts, Clock: clk, Lease: 40 * time.Second, Contacts: contacts}, engine.Options{Workers: 1})
	eh.WaitFor(hosts)
	silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	hosts.AddHandler(func(k informer.Key) {
		e.Changed(engine.Key{Kind: "Host", Name: k.Name})
		eh.Changed(engine.Key{Kind: "Host", Name: k.Name})
	})
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go e.Run(ctx)

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
	s := newSilo("validator")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop // after: 2m
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	waitFor(ctx, t, c, "validator", func(s *v1.Silo) bool { return s.Status.Host == "hv1" })
	go eh.Run(ctx) // from now on hv1's stamp is judged
	// hv1's agent arms its fence for this spec (the host lane's half).
	var got v1.Silo
	retry(t, func() error {
		_ = c.Get(ctx, "Silo", "dev", "validator", &got)
		meta.SetCondition(&got.Status.Conditions, fence.ArmedCondition("hv1", 2*time.Minute, got.Generation), clk.Now())
		return c.UpdateStatus(ctx, &got)
	})
	beat("hv2", t0)
	// hv1's stamp is an hour old by our clock: the lease calls it lost now. Its silo waits.
	waitFor(ctx, t, c, "validator", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, silo.CondHostUnreachable)
		return s.Status.Host == "hv1" && c != nil && c.Status == meta.ConditionTrue && strings.Contains(c.Message, "2m16s")
	})

	wait := 2*time.Minute + silo.StopMargin(2*time.Minute)
	clk.Step(wait - time.Second)
	beat("hv2", t0.Add(wait-time.Second))
	// One second short: still there. (Touching it makes the controller decide again now.)
	retry(t, func() error {
		_ = c.Get(ctx, "Silo", "dev", "validator", &got)
		got.Labels = map[string]string{"touch": "1"}
		return c.Update(ctx, &got)
	})
	waitFor(ctx, t, c, "validator", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, silo.CondHostUnreachable)
		return s.Status.Host == "hv1" && c != nil && strings.Contains(c.Message, "2m15s so far")
	})
	clk.Step(time.Second)
	waitFor(ctx, t, c, "validator", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, silo.CondHostUnreachable)
		return s.Status.Host == "hv2" && c != nil && c.Reason == "RestartedElsewhere"
	})
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
