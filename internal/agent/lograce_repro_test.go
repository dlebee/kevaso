package agent

import (
	"os"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri/fake"
)

// The data race seen once in a full `make race` of this package: an agent started with
// `go a.Run(ctx)` and Log: t.Logf keeps running (its engine workers log) after the test that
// started it returned, and its t.Logf then races with the testing package finishing that test
// (testing.go: destination() read against tRunner's write). Seen with
// TestASlowStartKeepsItsStartClaimFresh (k088_start_test.go), which returns right after
// close(rt.release) without cancelling its context or waiting for Run to return. The racing
// accesses are in TEST code (the Log hook is t.Logf); the product only logs, as it should.
//
// This is the smallest form: a subtest starts the agent and returns; the parent then makes the
// agent log. Skipped unless KEVASO_REPRO_LOGRACE=1, since under -race it fails by design:
//
//	KEVASO_REPRO_LOGRACE=1 go test -race -run TestReproAgentLogsAfterItsTestEnded ./internal/agent
//
// Fix, in the host lane's test: every test that starts the agent cancels its context and waits for
// Run to return (or passes a Log that checks a "done" flag under a mutex) before it returns.
func TestReproAgentLogsAfterItsTestEnded(t *testing.T) {
	if os.Getenv("KEVASO_REPRO_LOGRACE") == "" {
		t.Skip("reproduces a race in other tests' pattern on purpose: set KEVASO_REPRO_LOGRACE=1 (see the comment)")
	}
	var g *guardRig
	t.Run("starts the agent and returns", func(t *testing.T) {
		g = newGuardRig(t, fake.New(), nil)
		g.a.Log = t.Logf // this subtest's t
		go g.a.Run(g.ctx)
	})
	// The subtest is over, its agent still runs: a silo placed here makes it log.
	g.create(guardSilo("web", nil), "hv1", "")
	time.Sleep(2 * time.Second) // the agent reconciles and logs; the race detector sees it
}
