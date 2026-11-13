package openshell

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

func runningSandbox(t *testing.T) (*Runtime, *fake) {
	t.Helper()
	f := newFake()
	r := newRuntime(f, "")
	ctx := context.Background()
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	return r, f
}

func TestExecWithATerminal(t *testing.T) {
	r, f := runningSandbox(t)
	var got Cmd
	f.execHook = func(_ context.Context, c Cmd) (int, error) { got = c; return 0, nil }
	tty := &kri.TTY{Size: kri.WindowSize{Rows: 30, Cols: 100}}
	if _, err := r.Exec(context.Background(), silo, kri.ExecRequest{Command: []string{"bash"}, TTY: tty}); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(got.Args, " ")
	if strings.Contains(line, "--no-tty") || got.TTY != tty || !strings.HasSuffix(line, " bash") {
		t.Fatalf("openshell %s (tty %v)", line, got.TTY)
	}
}

// The client goes away mid-command: the sweep runs inside the sandbox with the exec's marker.
func TestExecCancelledSweepsTheSandbox(t *testing.T) {
	r, f := runningSandbox(t)
	var mu sync.Mutex
	var marker string
	var sweeps []string
	started := make(chan struct{})
	f.execHook = func(ctx context.Context, c Cmd) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		a := c.Args
		if i := indexOf(a, "--"); i > 0 && a[i+1] == "sh" && a[i+3] == hostexec.SweepScript {
			sweeps = append(sweeps, a[len(a)-1])
			return 0, nil
		}
		for _, x := range a {
			if v, ok := strings.CutPrefix(x, kri.ExecMarkerEnv+"="); ok {
				marker = v
			}
		}
		close(started)
		mu.Unlock()
		<-ctx.Done()
		mu.Lock()
		return -1, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"sleep", "1000"}})
		errc <- err
	}()
	<-started
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exec returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec didn't return")
	}
	mu.Lock()
	defer mu.Unlock()
	if marker == "" || len(sweeps) != 1 || sweeps[0] != marker {
		t.Fatalf("marker %q, sweeps %v", marker, sweeps)
	}
}

func indexOf(l []string, v string) int {
	for i, x := range l {
		if x == v {
			return i
		}
	}
	return -1
}
