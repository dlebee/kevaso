package agent_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// crashing is the fake whose machine fails right after every Start (a VMM that exits at boot).
type crashing struct {
	*fake.Runtime
	starts atomic.Int32
}

func (r *crashing) Start(ctx context.Context, id kri.ID) error {
	r.starts.Add(1)
	return r.Runtime.Start(ctx, id)
}

func (r *crashing) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	st, err := r.Runtime.Status(ctx, id)
	if err == nil && r.starts.Load() > 0 && st.State == kri.Running {
		st.State, st.Message = kri.Failed, "the VMM exited"
	}
	return st, err
}

// review-batch3 (C): a silo waiting out its restart backoff (a second crash in a row) holds no
// start claim. Before the fix the keeper of the start that crashed went on renewing it: each
// renewal a new claim, which resets the host's silence and blocks an opted-in silo's restart and
// --confirm-fenced while nothing starts.
func TestASiloWaitingOutItsRestartBackoffHoldsNoClaim(t *testing.T) {
	rt := &crashing{Runtime: fake.New()}
	r := newClaimRig(t, rt)
	r.a.ClaimRefresh = time.Second // renewals well inside the 10s backoff, on the fake clock
	agent.RunForTest(t, r.ctx, r.a)
	r.place()
	waiting := make(chan struct{})
	go func() {
		for r.ctx.Err() == nil {
			c := meta.FindCondition(r.get().Status.Conditions, "Ready")
			if c != nil && c.Reason == "RuntimeFailed" && strings.Contains(c.Message, "starting it again in") {
				close(waiting)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	r.waitIn("the silo waits out its restart backoff", waiting)
	time.Sleep(100 * time.Millisecond) // a renewal in flight lands
	last := claimOf(r.get())
	for range 5 { // 5s of the 10s backoff
		r.clk.Step(time.Second)
		time.Sleep(20 * time.Millisecond)
	}
	if now := claimOf(r.get()); now != last && now != "" {
		t.Fatalf("the start claim is still renewed while the silo waits out its backoff (nothing starts): %q, then %q", last, now)
	}
}
