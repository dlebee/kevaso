package silo

import (
	"context"
	"errors"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// failingKill is a runtime whose kill always fails: the silo runs on.
type failingKill struct{ *fake.Runtime }

func (failingKill) Kill(context.Context, kri.ID) error { return errors.New("engine refuses") }

// Rule 1 with kevasod dead: the agent armed the silo (FenceArmed True) and died; only the fence
// watcher is left on the host, and its kill fails on every check. Nothing on that host can reach
// the control plane (the watcher reads and writes local files only), so the silo stays armed in
// the API, and the control plane, past after + StopMargin of silence, starts a second copy while
// the first still runs. Needs a new mechanism (see the report: self-fence by reboot/watchdog when
// a kill can't be confirmed, or a positive "stopped" confirmation the control plane waits for).
func TestRule1AWatcherWhoseKillFailsStillLetsTheSiloRestartElsewhere(t *testing.T) {
	t.Skip("Rule 1, needs design: a failed watcher kill with kevasod dead leaves the silo armed")
	ctx := context.Background()
	after := 2 * time.Minute
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "db", UID: "u1", Generation: 1}}
	s.Spec.Runtime = "docker"
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop
	if stops, a := s.StopsOnControlPlaneLoss(); !stops || a != after {
		t.Fatalf("the silo doesn't opt in as expected: %v %v", stops, a)
	}
	s.Status.Host = "w1"
	// What the agent wrote while alive: the fence record, and FenceArmed in the API.
	meta.SetCondition(&s.Status.Conditions, fence.ArmedCondition("w1", after, 1), t0)

	rt := failingKill{fake.New()}
	id := kri.ID{Namespace: "dev", Name: "db", UID: "u1"}
	_ = rt.Create(ctx, kri.Spec{ID: id, Image: "x"})
	_ = rt.Start(ctx, id)
	dir := t.TempDir()
	if err := fence.Write(dir, fence.Record{Version: fence.RecordVersion, LastContact: t0, Written: t0,
		Silos: []fence.Silo{{ID: id, Runtime: "docker", StopAfter: after}}}); err != nil {
		t.Fatal(err)
	}
	// kevasod is dead from t0: the watcher checks every second until well past the control
	// plane's wait.
	wait := after + StopMargin(after)
	now := t0
	w := &fence.Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: fence.DefaultAfter,
		Now: func() time.Time { return now }, Boot: func() (string, time.Duration) { return "", 0 }, Log: func(string, ...any) {}}
	for now = t0; now.Before(t0.Add(wait + time.Minute)); now = now.Add(time.Second) {
		w.Check(ctx)
	}
	st, _ := rt.Status(ctx, id)
	if st.State != kri.Running {
		t.Fatalf("the first copy should still run (its kill fails): %v", st.State)
	}
	if ok, why := restartsItself(s, scheduler.Env{Silence: func(string) time.Duration { return wait + time.Minute }}); ok {
		t.Fatalf("Rule 1: the first copy still runs on w1 and the control plane starts another: %s", why)
	}
}
