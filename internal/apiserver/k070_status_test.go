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
	t.Skip("K-070: surface lane to fix (apiserver update: moves.Replaces on Silo status writes but the move handler's); see control-4.md")
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
