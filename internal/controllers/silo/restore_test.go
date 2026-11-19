package silo_test

import (
	"context"
	"net/http/httptest"
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
)

func TestAnUnsettledSiloIsNotPlaced(t *testing.T) {
	s := newSilo("a")
	g := &v1.RestoreGate{Spec: v1.RestoreGateSpec{History: "h2", Started: now.Add(time.Hour), NoHostsAdded: true, Required: []string{"hv1"}}}
	st, changed, _, err := silo.DecideIn(s, []*v1.Host{readyHost("hv1")}, nil, now, scheduler.Env{Restore: g})
	if err != nil || changed || st.Host != "" {
		t.Fatalf("unsettled was placed: %+v changed=%v %v", st, changed, err)
	}
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreSettled}
	st, changed, _, err = silo.DecideIn(s, []*v1.Host{readyHost("hv1")}, nil, now, scheduler.Env{Restore: g})
	if err != nil || !changed || st.Host != "hv1" {
		t.Fatalf("settled was not placed: %+v changed=%v %v", st, changed, err)
	}
}

func TestTheControllerDoesNotScheduleAnUnsettledSilo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	g := &v1.RestoreGate{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RestoreGate"},
		ObjectMeta: meta.ObjectMeta{Name: v1.RestoreGateName},
		Spec:       v1.RestoreGateSpec{History: "h2", Started: time.Now().Add(time.Hour).UTC(), NoHostsAdded: true, Required: []string{"hv1"}},
	}
	if err := c.Create(ctx, g); err != nil {
		t.Fatal(err)
	}
	h := readyHost("hv1")
	st := h.Status
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.Status = st
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, newSilo("web")); err != nil {
		t.Fatal(err)
	}
	silos, hosts, gates := informer.New(c, "Silo"), informer.New(c, "Host"), informer.New(c, "RestoreGate")
	ctrl := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Gates: gates, Clock: clock.Real{}}
	go silos.Run(ctx)
	go hosts.Run(ctx)
	go gates.Run(ctx)
	if !silos.WaitSynced(ctx) || !hosts.WaitSynced(ctx) || !gates.WaitSynced(ctx) {
		t.Fatal("caches never synced")
	}
	cacheShows(ctx, t, hosts, "", "hv1", func(o any) bool { return meta.IsTrue(o.(*v1.Host).Status.Conditions, "Ready") })
	if _, err := ctrl.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "web"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Host != "" {
		t.Fatalf("an unsettled silo was scheduled: %+v", got.Status)
	}
}
