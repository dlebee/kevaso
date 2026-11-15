package apiserver_test

import (
	"net/http"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// Review of the control-plane fixes, item 1: on a cluster (an authenticated server), only the
// host a silo is moving from ends its handoff (moves.Released, judged by HostWrite), or a person's
// confirm-fenced move through the move endpoint. A status write by anyone else that drops
// movingFrom, whatever it says of the volumes, is refused: else the destination starts the silo
// while the source still runs it. (A server with no authentication at all, which only tests
// build, has no identities to tell them apart.)
func TestOnAClusterOnlyTheSourceHostEndsAHandoff(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	_ = e.admin.Create(e.ctx, host("hv1"))
	_ = e.admin.Create(e.ctx, host("hv2"))
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
	if err := e.admin.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv2", "hv1", "Scheduled"
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	// The admin socket (and so any non-host caller) drops movingFrom: refused.
	var cur v1.Silo
	_ = e.admin.Get(e.ctx, "Silo", "dev", "web", &cur)
	cur.Status.MovingFrom = ""
	if err := e.admin.UpdateStatus(e.ctx, &cur); code(err) != http.StatusConflict {
		t.Fatalf("a non-host ended the handoff hv1 → hv2: %v, want 409", err)
	}
	// hv2, the destination, can't either.
	worker := func(name string) func(v1.Silo) error {
		tok, _ := e.tokens.Create(e.ctx, name, []string{"worker"}, time.Hour)
		cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, name, "worker")
		if err != nil {
			t.Fatal(err)
		}
		c := e.tlsClient(t, &cred)
		return func(s v1.Silo) error { return c.UpdateStatus(e.ctx, &s) }
	}
	_ = e.admin.Get(e.ctx, "Silo", "dev", "web", &cur)
	cur.Status.MovingFrom = ""
	if err := worker("hv2")(cur); code(err) != http.StatusForbidden {
		t.Fatalf("the destination ended the handoff: %v, want 403", err)
	}
	// hv1, the source, lets go.
	_ = e.admin.Get(e.ctx, "Silo", "dev", "web", &cur)
	released, ok := moves.Released(cur.Status, "hv1")
	if !ok {
		t.Fatal("not releasable")
	}
	cur.Status = released
	if err := worker("hv1")(cur); err != nil {
		t.Fatalf("the source letting go: %v", err)
	}
}
