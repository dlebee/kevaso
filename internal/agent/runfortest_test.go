package agent

import (
	"context"
	"sync"
	"testing"
	"time"
)

// RunForTest is how every test of this package runs an agent: a.Run(ctx) in a goroutine, ended
// by t's cleanup (its context cancelled, Run waited for), so nothing of the agent outlives the
// test that started it. a.Log, if set, is called only until then: the agent's other goroutines
// (its tunnels, its fence, a claim keeper's renewal) may still be finishing when Run returns, and
// a t.Logf after the test ended races with the testing package (the race the tests lane found,
// lograce_test.go). stop does the same earlier (a test that restarts its agent); it may be called
// more than once.
//
// A test that starts an agent any other way fails TestEveryAgentRunEndsWithItsTest.
func RunForTest(t testing.TB, ctx context.Context, a *Agent) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	ended := false
	if log := a.Log; log != nil {
		a.Log = func(f string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			if !ended {
				log(f, args...)
			}
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Errorf("the agent's Run didn't return within 20s of its context's end")
			}
			mu.Lock()
			ended = true
			mu.Unlock()
		})
	}
	t.Cleanup(stop)
	return stop
}
