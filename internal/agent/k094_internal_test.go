package agent

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// K-094: a silo whose fence kill here failed (or wasn't confirmed) is disarmed once the agent
// can say so (FenceArmed False, KillFailed): the control plane no longer restarts it elsewhere on
// the strength of a fence that didn't work. It stays disarmed until a kill of it is confirmed.
func TestASiloWhoseFenceKillFailedIsDisarmed(t *testing.T) {
	g := newGuardRig(t, nil, func(a *Agent) { a.FenceDir = t.TempDir() })
	s := g.create(guardSilo("db", func(s *v1.Silo) { s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop }), "hv1", "")
	f := &fencing{a: g.a, inflight: map[string]time.Time{}, unconfirmed: map[string]string{}}
	f.unconfirm(fenceTarget{runtime: "docker", id: kri.ID{Namespace: "dev", Name: "db", UID: s.UID}, after: time.Minute}, "the engine refused the kill")
	if err := g.a.armFence(g.ctx, s); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(g.stored("db").Status.Conditions, fence.ConditionArmed)
	if c == nil || c.Status != meta.ConditionFalse || c.Reason != "KillFailed" {
		t.Fatalf("a silo whose kill failed: FenceArmed %+v, want False KillFailed", c)
	}
}
