package agent_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// moveStored writes placement onto the stored silo (what a restart elsewhere, a restored or older
// store, or a person's --confirm-fenced move leaves).
func (e *env) moveStored(t *testing.T, name string, set func(*v1.SiloStatus)) {
	t.Helper()
	for {
		var cur v1.Silo
		if err := e.c.Get(e.ctx, "Silo", "dev", name, &cur); err != nil {
			t.Fatal(err)
		}
		set(&cur.Status)
		err := e.c.UpdateStatus(e.ctx, &cur)
		if err == nil {
			return
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
}

func (e *env) calls(op string) []string {
	var out []string
	for _, c := range e.rt.CallLog() {
		if strings.HasPrefix(c, op+" ") {
			out = append(out, c)
		}
	}
	return out
}

// Review claim A: a silo the store places on another host, with no handoff from this host, is
// stopped here and kept, its root disk with it: only a delete this host saw, or a handoff it took
// part in, removes a silo's disk. (A microVM's Delete removes its root logical volume.)
func TestASiloPlacedElsewhereWithoutAHandoffIsStoppedAndKept(t *testing.T) {
	e := setup(t)
	e.place(t, "db", "hv1", nil)
	s := e.wait(t, "db", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
	e.moveStored(t, "db", func(st *v1.SiloStatus) { st.Host, st.Phase, st.MovingFrom = "hv2", "Scheduled", "" })
	id := kri.ID{Namespace: "dev", Name: "db", UID: s.UID}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		st, _ := e.rt.Status(e.ctx, id)
		if st.State != kri.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still running here after it was placed on hv2")
		}
	}
	time.Sleep(time.Second) // the agent's next looks
	if d := e.calls("delete"); len(d) > 0 {
		t.Fatalf("deleted (its root disk with it) though no delete was seen and no handoff from here released it: %v", e.rt.CallLog())
	}
	if st, _ := e.rt.Status(e.ctx, id); st.State == kri.Absent || st.State == kri.Running {
		t.Fatalf("want stopped and kept, got %s", st.State)
	}
}

// A handoff from this host (movingFrom: this host) is a move this host takes part in: the copy
// here goes and the host lets go, as before.
func TestAHandoffFromHereStillRemovesTheCopyAndReleases(t *testing.T) {
	e := setup(t)
	e.place(t, "web", "hv1", nil)
	e.wait(t, "web", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
	e.moveStored(t, "web", func(st *v1.SiloStatus) { st.Host, st.Phase, st.MovingFrom = "hv2", "Scheduled", "hv1" })
	e.wait(t, "web", func(s *v1.Silo) bool { return s.Status.MovingFrom == "" })
	if len(e.calls("delete")) == 0 {
		t.Fatalf("a handed-off copy wasn't removed: %v", e.rt.CallLog())
	}
}
