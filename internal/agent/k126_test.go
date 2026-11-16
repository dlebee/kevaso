package agent_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// stopHeld is a runtime whose Stop waits while hold is set, and returns when the caller's
// context ends: kevasod can be restarted after a new history is accepted and before that stop
// finishes. A later Stop, once hold is cleared, runs as usual.
type stopHeld struct {
	*fake.Strict
	mu   sync.Mutex
	hold <-chan struct{}
}

func (s *stopHeld) Stop(ctx context.Context, id kri.ID) error {
	s.mu.Lock()
	hold := s.hold
	s.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Strict.Stop(ctx, id)
}

func (s *stopHeld) setHold(h <-chan struct{}) {
	s.mu.Lock()
	s.hold = h
	s.mu.Unlock()
}

// K-126: kevasod restarts after a new history is accepted and before the stop of a copy whose
// handoff is a restore's replay has finished. The copy and its root disk stay. The runtime
// records no delete.
func TestARestartAfterANewHistoryKeepsTheCopyAndItsDisk(t *testing.T) {
	r := newHistoryRig(t)
	held := &stopHeld{Strict: r.rt}
	stop := r.start(held)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	// Stops wait: the restart lands after the new history is on disk and before this stop ends.
	held.setHold(make(chan struct{}))
	r.cp.switchTo(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "restoring", http.StatusServiceUnavailable)
	}), seenA)
	for {
		var cur v1.Silo
		if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.Host, cur.Status.MovingFrom = "hv2", "hv1"
		err := r.cA.UpdateStatus(r.ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	r.cp.switchTo(r.srvA, seenRestor)
	r.trusted(seenRestor)
	stop()
	held.setHold(nil)
	r.start(held)
	r.waitFor("the copy is stopped and its disk is still here", func() bool {
		for _, c := range r.rt.CallLog() {
			if strings.HasPrefix(c, "delete ") {
				t.Fatalf("the root disk was deleted after kevasod restarted: %v", r.rt.CallLog())
			}
		}
		if !holds(t, r.rt, r.id.UID) {
			t.Fatalf("the copy is gone after kevasod restarted: %v", r.rt.CallLog())
		}
		st, _ := r.rt.Status(r.ctx, r.id)
		return st.State != kri.Running
	})
	for _, c := range r.rt.CallLog() {
		if strings.HasPrefix(c, "delete ") {
			t.Fatalf("the root disk was deleted after kevasod restarted: %v", r.rt.CallLog())
		}
	}
	r.keptFor(r.id, 2*time.Second)
	r.listed(r.cA, r.id)
}
