package agent

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri/fake"
)

// The data race the tests lane found (1 in about 25 loaded runs of `make race`): an agent started
// with `go a.Run(ctx)` and Log: t.Logf kept running (its engine workers log) after the test that
// started it returned, and its t.Logf then raced with the testing package finishing that test
// (testing.go: destination() read against tRunner's write). First seen with
// TestASlowStartKeepsItsStartClaimFresh, which returned right after close(rt.release) without
// cancelling its context or waiting for Run. The racing accesses were in test code (the Log hook
// is t.Logf); the product only logs, as it should.
//
// Here: a subtest starts the agent and returns; the parent then makes the agent act (a silo placed
// on its host whose create fails), which logs. With RunForTest the agent ended with the subtest
// and logs nothing after it; with `go g.a.Run(g.ctx)` in its place it logs after its test ended
// (each such log is a chance for the race above, which -race catches about once in 25 runs: this
// test counts the logs instead, so it fails every time).
func TestAnAgentNeverLogsAfterTheTestThatStartedItEnded(t *testing.T) {
	rt := fake.New()
	rt.FailCreate["web"] = errors.New("no space left") // the agent logs each failed create
	g := newGuardRig(t, rt, nil)
	var mu sync.Mutex
	ended, late := false, []string{}
	t.Run("starts the agent and returns", func(t *testing.T) {
		g.a.Log = func(f string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			if ended {
				late = append(late, fmt.Sprintf(f, args...))
				return
			}
			t.Logf(f, args...)
		}
		RunForTest(t, g.ctx, g.a)
	})
	mu.Lock()
	ended = true
	mu.Unlock()
	g.create(guardSilo("web", nil), "hv1", "")
	time.Sleep(time.Second) // an agent still running would reconcile it and log now
	mu.Lock()
	defer mu.Unlock()
	if len(late) > 0 {
		t.Fatalf("the agent logged %d times after the test that started it ended, first: %s", len(late), late[0])
	}
}

// Every test of this package runs its agent through RunForTest, so none outlives its test: a
// `go a.Run(ctx)` (or a goroutine around Run) in a test file is the race above waiting to happen.
func TestEveryAgentRunEndsWithItsTest(t *testing.T) {
	bare := regexp.MustCompile(`\bgo\s+(func\s*\(\)\s*\{[^\n]*)?\b[\w.]+\.Run\(`)
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		name := f.Name()
		if !strings.HasSuffix(name, "_test.go") || name == "runfortest_test.go" || name == "lograce_test.go" {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bare.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Errorf("%s:%d: %s: run the agent with RunForTest (it ends with the test)", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
