package hostexec

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// Brief item C (kevasod took 90s to stop on machine 2): a host command that leaves a process
// holding its output (a daemon it forked, a grandchild its kill missed) mustn't hold Run, and so
// the agent's reconcile and kevasod's stop, until that process ends. Before WaitDelay, both cases
// waited the leftover's 20s.
func TestACommandThatLeavesItsOutputOpenDoesNotHoldRun(t *testing.T) {
	t.Run("its context ends", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var out bytes.Buffer
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		began := time.Now()
		_, _ = Local{}.Run(ctx, Cmd{Name: "sh", Args: []string{"-c", "sleep 20 & sleep 20"}, Stdout: &out, Stderr: &out})
		if took := time.Since(began); took > 10*time.Second {
			t.Fatalf("Run returned %s after its context ended", took.Round(time.Second))
		}
	})
	t.Run("it exits", func(t *testing.T) {
		var out bytes.Buffer
		began := time.Now()
		code, err := Local{}.Run(context.Background(), Cmd{Name: "sh", Args: []string{"-c", "sleep 20 & echo up; exit 3"}, Stdout: &out, Stderr: &out})
		if took := time.Since(began); took > 10*time.Second {
			t.Fatalf("Run returned %s after the command exited", took.Round(time.Second))
		}
		if err != nil || code != 3 || !strings.Contains(out.String(), "up") {
			t.Fatalf("Run: %d %v %q, want its exit code 3 and its output", code, err, out.String())
		}
	})
}
