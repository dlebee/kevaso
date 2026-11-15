package apiserver_test

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
	"kevaso.com/core/internal/store"
)

// K-070 (surface lane): whatever the caller does, a status write that drops or replaces a
// handoff under way is refused (409), as moves.Replaces judges it. Today an admin's PUT of
// silos/status (kvoadm host drain writes one) rewrites movingFrom freely. The move handler's
// confirmed-fenced end of a handoff (PlanMove) is the one exception and must keep working
// (TestK013HandoffFromALostSourceEndsWithConfirmFenced).
func TestK070AStatusWriteNeverReplacesAHandoff(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "D", "S", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "", "D", "Pending" // what drain of D writes
	if err := c.UpdateStatus(ctx, s); !client.IsConflict(err) {
		t.Fatalf("a status write replaced the handoff S → D: %v, want a Conflict", err)
	}
}

// K-070, next to it: unplacing a silo and dropping its handoff, or naming another source, is refused;
// a write that keeps the handoff, ends it with the silo still on its destination (the source let
// go), or puts the silo back on S, is not.
func TestK070AStatusWriteKeepsOrEndsAHandoffOnlyAsReplacesAllows(t *testing.T) {
	ctx := context.Background()
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "D", "S", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "", "", "Pending" // unplaced, the handoff gone
	if err := c.UpdateStatus(ctx, s); !client.IsConflict(err) {
		t.Fatalf("a status write unplaced the silo and dropped the handoff S → D: %v, want a Conflict", err)
	}
	if err := c.Get(ctx, "Silo", "d", "s", s); err != nil {
		t.Fatal(err)
	}
	s.Status.MovingFrom = "X" // another source
	if err := c.UpdateStatus(ctx, s); !client.IsConflict(err) {
		t.Fatalf("a status write named another source: %v, want a Conflict", err)
	}
	if err := c.Get(ctx, "Silo", "d", "s", s); err != nil {
		t.Fatal(err)
	}
	s.Status.Phase = "Starting" // keeps the handoff
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatalf("a write that keeps the handoff: %v", err)
	}
	s.Status.MovingFrom = "" // S let go: the silo stays on D
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatalf("a write ending the handoff on D: %v", err)
	}
	s.Status.Host, s.Status.MovingFrom = "D", "S"
	if err := c.UpdateStatus(ctx, s); err != nil { // a new handoff begins
		t.Fatalf("a write beginning a handoff: %v", err)
	}
	s.Status.Host, s.Status.MovingFrom = "S", "" // back on S: nothing to hand off
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatalf("a write putting the silo back on S: %v", err)
	}
}
