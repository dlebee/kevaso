package agent

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
)

// Brainstorm §0.7, the agent's half of onControlPlaneLoss: Stop (host lane; the control plane's
// half is in internal/controllers/silo and internal/fence). The agent's fence record must be
// version 2: each silo with its StopAfter from (*v1.Silo).StopsOnControlPlaneLoss() (0 when it
// continues), whatever onHostLoss says; LastContact the time the last successful heartbeat write
// was SENT. Once that record is on disk, the agent writes fence.ArmedCondition(host, after,
// generation) on the silo's status; the control plane restarts the silo elsewhere only while
// fence.Armed holds. The agent's own fence (agent.go, a.fenced) follows the same rule: it stops
// only StopAfter silos, each after its own after.
func TestStopSilosAreRecordedWithTheirAfter(t *testing.T) {
	t.Skip("brainstorm §0.7, host lane: write fence record version 2 with StopAfter, and fence.ArmedCondition; remove this skip with that change")
	dir := t.TempDir()
	a := &Agent{HostName: "hv1", Clock: clock.Real{}, LastContact: time.Now, FenceDir: dir}
	stop := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "validator", Namespace: "dev", UID: "u1", Generation: 2}}
	stop.Spec.Runtime = "docker"
	stop.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	stop.Spec.Availability.OnControlPlaneLoss, stop.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	keep := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", UID: "u2", Generation: 1}}
	keep.Spec.Runtime = "docker"
	keep.Spec.Availability.OnHostLoss = v1.OnHostLossMove // moves on a confirmation only: never stopped by a fence
	for _, s := range []*v1.Silo{stop, keep} {
		if err := a.recordForFence(s); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fence.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != fence.RecordVersion {
		t.Fatalf("record version %d, want %d", r.Version, fence.RecordVersion)
	}
	for _, s := range r.Silos {
		want := map[string]time.Duration{"u1": 45 * time.Second, "u2": 0}[s.ID.UID]
		if s.StopAfter != want {
			t.Errorf("%s: StopAfter %v, want %v", s.ID.Name, s.StopAfter, want)
		}
	}
}
