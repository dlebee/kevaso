package agent

import (
	"testing"
)

// T-14, mayRemove's first check: an answer the worker can't act on (it is held: a system node
// behind answered) is proof of nothing. Here the store says a handoff from this host, which would
// remove the copy: held, mayRemove removes nothing and says why.
func TestAHeldAnswerIsNoProofForARemoval(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("single", nil), "hv2", "hv1") // handed off from here
	w := g.a.watermark()
	w.mu.Lock()
	w.kept.Held = true
	w.mu.Unlock()
	remove, why, err := g.a.mayRemove(g.ctx, idOf(s))
	if remove || err == nil {
		t.Fatalf("held, mayRemove says remove=%v (%q, %v): a held answer is taken as proof", remove, why, err)
	}
	w.mu.Lock()
	w.kept.Held = false
	w.mu.Unlock()
	if remove, why, err := g.a.mayRemove(g.ctx, idOf(s)); !remove || why != whyHandoff || err != nil {
		t.Fatalf("not held, a handoff from here: remove=%v (%q, %v)", remove, why, err)
	}
}
