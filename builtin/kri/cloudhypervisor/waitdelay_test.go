package cloudhypervisor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Brief item C, as hostexec's: a command that leaves a process holding its output doesn't hold
// the runtime's call (and kevasod's stop) until that process ends.
func TestAHostCommandThatLeavesItsOutputOpenDoesNotHoldTheRuntime(t *testing.T) {
	t.Run("its context ends", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		began := time.Now()
		_, _ = Local{}.Run(ctx, "sh", "-c", "sleep 20 & sleep 20")
		if took := time.Since(began); took > 10*time.Second {
			t.Fatalf("Run returned %s after its context ended", took.Round(time.Second))
		}
	})
	t.Run("it exits", func(t *testing.T) {
		began := time.Now()
		out, err := Local{}.Run(context.Background(), "sh", "-c", "sleep 20 & echo up")
		if took := time.Since(began); took > 10*time.Second {
			t.Fatalf("Run returned %s after the command exited", took.Round(time.Second))
		}
		if err != nil || !strings.Contains(string(out), "up") {
			t.Fatalf("Run: %v %q, want success and its output", err, out)
		}
	})
}
