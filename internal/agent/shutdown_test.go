package agent_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// stuckStart is the fake whose Start doesn't end with its context (an engine or host command that
// doesn't answer): it returns when the test lets it.
type stuckStart struct {
	*fake.Runtime
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *stuckStart) Start(ctx context.Context, id kri.ID) error {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.Runtime.Start(ctx, id)
}

// Brief item C (machine 2: kevasod took 90s to stop, then systemd killed it): a stopping agent
// waits for its reconciles under way only so long, names what it left, and returns, well inside
// systemd's stop timeout. The silo isn't stopped for it.
func TestAStoppingAgentDoesNotWaitForeverForAReconcile(t *testing.T) {
	rt := &stuckStart{Runtime: fake.New(), entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() { close(rt.release) })
	r := newClaimRig(t, rt)
	var mu sync.Mutex
	var logs []string
	r.a.Log = func(f string, args ...any) {
		mu.Lock()
		logs = append(logs, f)
		mu.Unlock()
		t.Logf(f, args...)
	}
	r.a.ShutdownWait = time.Second
	stop := agent.RunForTest(t, r.ctx, r.a) // its stop is kevasod's SIGTERM: the run's context ends
	r.place()
	r.waitIn("the start begins", rt.entered)
	began := time.Now()
	stop()
	if took := time.Since(began); took > 10*time.Second {
		t.Fatalf("the agent's Run returned %s after its context ended, a reconcile still under way", took.Round(time.Second))
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logs {
		if strings.HasPrefix(l, "stopping after") {
			return
		}
	}
	t.Fatalf("it never said what it left: %q", logs)
}
