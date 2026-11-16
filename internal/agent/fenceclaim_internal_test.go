package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// holdKill blocks in Kill until release is closed, so a test can change the silo while the
// kill is in flight.
type holdKill struct {
	*fake.Runtime
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *holdKill) Kill(ctx context.Context, id kri.ID) error {
	h.once.Do(func() { close(h.entered) })
	select {
	case <-h.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return h.Runtime.Kill(ctx, id)
}

// Rule 1: a kill still in flight when contact returns must not report FenceStopped for a start
// claim stored while that kill ran. That claim is a start that may run here; a report of it would
// let the control plane start another copy.
func TestAKillInFlightWhenContactReturnsDoesNotVouchForTheNewStart(t *testing.T) {
	inner := fake.New()
	rt := &holdKill{Runtime: inner, entered: make(chan struct{}), release: make(chan struct{})}
	g := newGuardRig(t, rt, nil)
	var back atomic.Bool
	g.a.LastContact = func() time.Time {
		if back.Load() {
			return time.Now()
		}
		return time.Now().Add(-time.Hour)
	}
	g.a.started = time.Now().Add(-2 * time.Hour)

	s := g.create(stopAfter("1m"), "hv1", "")
	old := startClaim("hv1", s.Generation, time.Now().Add(-time.Hour).UTC())
	s.Status.Conditions = append(s.Status.Conditions, old)
	if err := g.c.UpdateStatus(g.ctx, s); err != nil {
		t.Fatal(err)
	}
	s = g.stored("web")
	g.cacheIs(s)
	id := idOf(s)
	if err := inner.Create(g.ctx, kri.Spec{ID: id, Image: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := inner.Start(g.ctx, id); err != nil {
		t.Fatal(err)
	}

	f := &fencing{a: g.a, inflight: map[string]time.Time{}, unconfirmed: map[string]string{}}
	done := make(chan struct{})
	go func() {
		f.stop(g.ctx, fenceTarget{rt: rt, runtime: "docker", id: id, after: time.Minute})
		close(done)
	}()
	select {
	case <-rt.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the kill never started")
	}

	// Contact is back, and a start here has claimed, before the kill returns. The process is not
	// running yet: the kill is what stops it.
	back.Store(true)
	cur := g.stored("web")
	var conds []meta.Condition
	for _, c := range cur.Status.Conditions {
		if c.Type != ConditionStartClaim {
			conds = append(conds, c)
		}
	}
	newer := startClaim("hv1", cur.Generation, time.Now().UTC())
	cur.Status.Conditions = append(conds, newer)
	if err := g.c.UpdateStatus(g.ctx, cur); err != nil {
		t.Fatal(err)
	}
	g.cacheIs(g.stored("web"))
	close(rt.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the kill didn't return")
	}

	_, stopped := f.endOutage()
	g.a.reportStopped(g.ctx, stopped)
	if c := meta.FindCondition(g.stored("web").Status.Conditions, fence.ConditionStopped); c != nil && c.Message == fence.StoppedCondition("hv1", &newer, cur.Generation).Message {
		t.Fatalf("FenceStopped stands for the start claimed while the kill was in flight: %+v", c)
	}
}
