package agent

import (
	"fmt"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/fence"
)

// A kill this host could not confirm stays disarmed across a restart of kevasod. The FenceArmed
// condition is what says so; a new process has an empty memory of the fault. A kill confirmed in
// the new process arms it again.
func TestAKillFailureStaysDisarmedAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	g := newGuardRig(t, nil, func(a *Agent) { a.FenceDir = dir })
	if err := fence.WriteStamp(dir, fence.Stamp{Version: fence.RecordVersion, BootID: boottime.ID(), Boot: boottime.Now(), At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s := g.create(stopAfter("1m"), "hv1", "")
	s.Status.Conditions = append(s.Status.Conditions, meta.Condition{
		Type: fence.ConditionArmed, Status: meta.ConditionFalse, Reason: "KillFailed",
		Message:            fmt.Sprintf("the fence on %s couldn't confirm this silo stopped in the last outage (the engine refused the kill): not armed until a kill of it there is confirmed", g.a.HostName),
		ObservedGeneration: s.Generation,
	})
	if err := g.c.UpdateStatus(g.ctx, s); err != nil {
		t.Fatal(err)
	}
	s = g.stored("web")
	g.cacheIs(s)

	// A new process: the in-memory fault is gone, the condition is what was stored.
	if err := g.a.armFence(g.ctx, s); err != nil {
		t.Fatal(err)
	}
	c := meta.FindCondition(g.stored("web").Status.Conditions, fence.ConditionArmed)
	if c == nil || c.Status != meta.ConditionFalse || c.Reason != "KillFailed" {
		t.Fatalf("after a restart the silo was armed again: FenceArmed %+v, want False KillFailed", c)
	}

	// A kill confirmed in this process: armed again.
	g.a.LastContact = func() time.Time { return time.Now().Add(-time.Hour) }
	g.a.started = time.Now().Add(-2 * time.Hour)
	f := &fencing{a: g.a, inflight: map[string]time.Time{}, unconfirmed: map[string]string{}}
	f.stop(g.ctx, fenceTarget{rt: g.rt, runtime: "docker", id: idOf(s), after: time.Minute})
	if err := g.a.armFence(g.ctx, g.stored("web")); err != nil {
		t.Fatal(err)
	}
	if got := g.stored("web"); !fence.Armed(got) {
		t.Fatalf("a confirmed kill left it disarmed: %+v", meta.FindCondition(got.Status.Conditions, fence.ConditionArmed))
	}
}
