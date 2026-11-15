package agent

import (
	"context"
	"sync"
	"time"

	"kevaso.com/core/internal/clock"
)

// tick sends on the channel it returns every d, on the agent's Clock, until ctx ends: what
// time.NewTicker does, but a test that gives the agent a clock.Fake drives the fence, the resync and
// the watch of the control plane by stepping it, with no sleeps. A tick the reader hasn't taken
// yet isn't doubled (as with time.Ticker).
func (a *Agent) tick(ctx context.Context, d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	var mu sync.Mutex
	var t clock.Timer
	var fire func()
	fire = func() {
		select {
		case ch <- a.Clock.Now():
		default:
		}
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() == nil {
			t = a.Clock.AfterFunc(d, fire)
		}
	}
	mu.Lock()
	t = a.Clock.AfterFunc(d, fire)
	mu.Unlock()
	go func() {
		<-ctx.Done()
		mu.Lock()
		t.Stop()
		mu.Unlock()
	}()
	return ch
}
