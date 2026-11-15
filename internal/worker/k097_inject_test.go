package worker

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// K-097, the gate's injections: while held, the control plane's answers aren't used. What this
// host was given before the hold is injected (no call made), for at most InjectWithoutContact; a
// change the older control plane reports doesn't drop it; nothing new is given and no approval
// is asked.
func TestAHeldHostInjectsOnlyWhatItWasGivenBefore(t *testing.T) {
	e, b, clock, _ := injectRig(t)
	var held atomic.Bool
	e.held = held.Load
	ctx := context.Background()
	if _, err := e.injections(ctx, "dev/claude-1"); err != nil {
		t.Fatal(err)
	}
	held.Store(true)
	b.mode.Store("refuse") // the older control plane says something else
	calls := b.calls.Load()
	clock.add(5 * time.Minute)
	e.invalidate() // a Secret or Grant "changed" in the older control plane's lists
	got, err := e.injections(ctx, "dev/claude-1")
	if err != nil || got["api.allowed.test"].Value != "Bearer sk-1" {
		t.Fatalf("held: %v %v, want what was given before the hold", got, err)
	}
	if b.calls.Load() != calls {
		t.Error("held: the control plane was asked")
	}
	if err := e.ask(ctx, "dev/claude-1", "key", "api.allowed.test", "GET", "/"); err == nil || b.calls.Load() != calls {
		t.Errorf("held: an approval was asked of the control plane (%v)", err)
	}
	clock.add(time.Hour)
	if _, err := e.injections(ctx, "dev/claude-1"); err == nil || !strings.Contains(err.Error(), "held") {
		t.Fatalf("held past the hour: %v", err)
	}
	// Another silo of the host, never given anything: nothing while held.
	e2, b2, _, _ := injectRig(t)
	e2.held = func() bool { return true }
	if _, err := e2.injections(ctx, "dev/claude-1"); err == nil || b2.calls.Load() != 0 {
		t.Fatalf("held, nothing given before: %v, %d calls", err, b2.calls.Load())
	}
	held.Store(false)
	b.mode.Store("up")
	if got, err := e.injections(ctx, "dev/claude-1"); err != nil || got["api.allowed.test"].Value != "Bearer sk-1" {
		t.Fatalf("the hold ended: %v %v", got, err)
	}
}
