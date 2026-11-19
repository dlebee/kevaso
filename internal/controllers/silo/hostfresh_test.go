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
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// A silo whose host is missing from the cache is not marked Unschedulable/HostDeleted when a
// fresh read finds the Host. NotFound is what marks it.
func TestASiloOnAHostTheCacheMissesIsNotMarkedDeleted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	hosts := frozen(ctx, t, c, "Host") // empty: hv1 is created after this
	h := readyHost("hv1")
	st := h.Status
	if err := c.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.Status = st
	if err := c.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	s := newSilo("pin")
	s.Spec.Volumes = []v1.Volume{{Name: "data", Class: v1.VolumeLocal, Size: "1Gi", MountPath: "/data"}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Silo", "dev", "pin", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	silos := frozen(ctx, t, c, "Silo")
	ctrl := &silo.Controller{Client: c, Silos: silos, Hosts: hosts, Clock: clock.Real{}}
	if _, err := ctrl.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "pin"}); err != nil {
		t.Fatal(err)
	}
	var got v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "pin", &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Host != "hv1" {
		t.Fatalf("host %q", got.Status.Host)
	}
	if cond := meta.FindCondition(got.Status.Conditions, moves.CondUnschedulable); cond != nil && cond.Reason == moves.ReasonHostDeleted {
		t.Fatalf("marked deleted from a cache that had not seen hv1: %+v", cond)
	}
}
