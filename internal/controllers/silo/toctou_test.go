package silo_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
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

type placeEnv struct {
	ctx context.Context
	t   *testing.T
	c   *client.Client
	clk *clock.Fake
}

func newPlaceEnv(t *testing.T) *placeEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	clk := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	srv, err := apiserver.New(store.NewMemory(0), clk)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	e := &placeEnv{ctx: ctx, t: t, c: client.New(ts.URL), clk: clk}
	_ = e.c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	return e
}

func (e *placeEnv) host(h *v1.Host) {
	e.t.Helper()
	st := h.Status
	if err := e.c.Create(e.ctx, h); err != nil {
		e.t.Fatal(err)
	}
	h.Status = st
	if err := e.c.UpdateStatus(e.ctx, h); err != nil {
		e.t.Fatal(err)
	}
}

func (e *placeEnv) get(kind, ns, name string, out meta.Object) {
	e.t.Helper()
	if err := e.c.Get(e.ctx, kind, ns, name, out); err != nil {
		e.t.Fatal(err)
	}
}

// Review (check-then-act) item 4: a placement decided from a host cache must not land on a host
// cordoned since: the host it places on is read fresh right before the write.
func TestAPlacementIsNotMadeOnAHostCordonedSinceTheRead(t *testing.T) {
	e := newPlaceEnv(t)
	e.host(readyHost("hv1"))
	s := newSilo("web")
	s.Spec.Placement.HostSelector = nil
	if err := e.c.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	ctl := &silo.Controller{Client: e.c, Silos: frozen(e.ctx, t, e.c, "Silo"), Hosts: frozen(e.ctx, t, e.c, "Host"), Clock: e.clk}
	var h v1.Host
	e.get("Host", "", "hv1", &h)
	h.Spec.Unschedulable = true // kvoadm host drain cordons it
	if err := e.c.Update(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Reconcile(e.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	e.get("Silo", "dev", "web", &got)
	if got.Status.Host == "hv1" {
		t.Fatal("placed on hv1, cordoned after the controller's read")
	}
}

// …and an opted-in silo is not restarted elsewhere while its host, lost in the cache, is
// heartbeating in the store: the old host is read fresh and its heartbeat counted.
func TestARestartElsewhereReadsTheOldHostFresh(t *testing.T) {
	e := newPlaceEnv(t)
	t0 := e.clk.Now()
	old := lostHost("hv1", t0.Add(-time.Hour))
	stamp := t0.Add(-time.Hour)
	old.Status.LastHeartbeat = &stamp
	e.host(old)
	e.host(readyHost("hv2"))
	s := newSilo("validator")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	if err := e.c.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.get("Silo", "dev", "validator", s)
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, s.Generation)}
	if err := e.c.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	contacts := hostctl.NewContacts(t0)
	e.clk.Step(time.Hour) // by our count, an hour without a word from hv1…
	ctl := &silo.Controller{Client: e.c, Silos: frozen(e.ctx, t, e.c, "Silo"), Hosts: frozen(e.ctx, t, e.c, "Host"), Clock: e.clk, Contacts: contacts}
	// …but hv1 is back, heartbeating: the store has it, the cache doesn't.
	var h v1.Host
	e.get("Host", "", "hv1", &h)
	beat := e.clk.Now()
	h.Status.LastHeartbeat = &beat
	h.Status.Conditions = readyHost("hv1").Status.Conditions
	if err := e.c.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatal(err)
	}
	if _, err := ctl.Reconcile(e.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "validator"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	e.get("Silo", "dev", "validator", &got)
	if got.Status.Host != "hv1" {
		t.Fatalf("restarted on %q while hv1 heartbeats (a host cache behind): two copies", got.Status.Host)
	}
}
