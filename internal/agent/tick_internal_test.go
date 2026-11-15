package agent

import (
	"context"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
)

// The seam the tests lane asked for: the agent's fence, resync and control-plane watch tick on
// its Clock, so a clock.Fake steps them with no sleeps.
func TestTheAgentsTicksFollowItsClock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := clock.NewFake(time.Unix(1_000_000, 0))
	a := &Agent{Clock: c}
	ticks := a.tick(ctx, time.Second)
	select {
	case <-ticks:
		t.Fatal("a tick before the clock moved")
	default:
	}
	for i := 0; i < 3; i++ {
		c.Step(time.Second)
		select {
		case at := <-ticks:
			if !at.Equal(c.Now()) {
				t.Fatalf("tick at %v, clock at %v", at, c.Now())
			}
		case <-time.After(time.Second):
			t.Fatalf("no tick after step %d", i+1)
		}
	}
	cancel()
	for deadline := time.Now().Add(time.Second); c.Pending() > 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("still ticking after its context ended")
		}
	}
}
