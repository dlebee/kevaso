package hostexec

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

// The sweep finds a process by its marker and kills it, and nothing else (Linux: it reads /proc).
func TestSweepKillsTheMarkedProcess(t *testing.T) {
	if _, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no /proc here")
	}
	marker := NewMarker()
	start := func(m string) *exec.Cmd {
		c := exec.Command("sleep", "30")
		c.Env = []string{kri.ExecMarkerEnv + "=" + m}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
		return c
	}
	mine, other := start(marker), start("other")
	// Until the children have exec'd, /proc shows the parent's environment.
	deadline := time.Now().Add(5 * time.Second)
	for {
		pids := MarkedPIDs(Local{}, marker)
		if len(pids) == 1 && pids[0] == mine.Process.Pid {
			break
		}
		if len(pids) > 1 || time.Now().After(deadline) {
			t.Fatalf("marked %v, want [%d]", pids, mine.Process.Pid)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if out, err := exec.Command("sh", "-c", SweepScript, "sh", marker).CombinedOutput(); err != nil {
		t.Fatalf("sweep: %v %s", err, out)
	}
	done := make(chan struct{})
	go func() { _ = mine.Wait(); close(done) }()
	select {
	case <-done: // killed: Wait's error says so
	case <-time.After(5 * time.Second):
		t.Fatal("the marked process is still running")
	}
	if _, err := os.Stat("/proc/" + strconv.Itoa(other.Process.Pid)); err != nil {
		t.Fatal("the sweep killed an unmarked process")
	}
}
