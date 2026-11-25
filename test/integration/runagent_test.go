package integration

import (
	"context"

	"kevaso.com/core/internal/agent"
)

// runAgent starts a's Run and returns what stops it: its context's end, then Run's return. Call it
// as `defer runAgent(ctx, a)()`. A defer runs before every t.Cleanup, so the agent has stopped
// writing (secret files, a silo's root) before the test's folders are removed; a goroutine left
// running raced that removal ("directory not empty").
func runAgent(ctx context.Context, a *agent.Agent) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()
	return func() { cancel(); <-done }
}
