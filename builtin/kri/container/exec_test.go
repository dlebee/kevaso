package container

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

func runningSilo(t *testing.T) (*Runtime, *fake) {
	t.Helper()
	f := newFake()
	r := runtime(t, f)
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
	r, f := runningSilo(t)
	var got hostexec.Cmd
	f.execHook = func(_ context.Context, c hostexec.Cmd) (int, error) { got = c; return 0, nil }
	tty := &kri.TTY{Size: kri.WindowSize{Rows: 40, Cols: 120}}
	if _, err := r.Exec(context.Background(), silo, kri.ExecRequest{Command: []string{"bash", "-l"}, Stdin: strings.NewReader(""), TTY: tty}); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(got.Args, " ")
	if !strings.HasPrefix(line, "exec -i -t -e TERM=xterm-256color -e KEVASO_EXEC=") || !strings.HasSuffix(line, NamesFor(silo).Main+" bash -l") {
		t.Fatalf("docker %s", line)
	}
	if got.TTY != tty {
		t.Fatal("the engine's CLI didn't get a terminal to pass on")
	}
}

// proc puts one process in the fake host's /proc: its stat (parent, session), cgroup, environment.
func proc(f *fake, pid, ppid, sid int, cgroup string, env ...string) {
	stat := fmt.Sprintf("%d (some (odd) name) S %d %d %d 0 -1", pid, ppid, sid, sid)
	_ = f.WriteFile(fmt.Sprintf("/proc/%d/stat", pid), []byte(stat), 0o644)
	_ = f.WriteFile(fmt.Sprintf("/proc/%d/cgroup", pid), []byte(cgroup), 0o644)
	e := ""
	for _, v := range env {
		e += v + "\x00"
	}
	_ = f.WriteFile(fmt.Sprintf("/proc/%d/environ", pid), []byte(e), 0o644)
}

const (
	inSilo  = "0::/system.slice/docker-abc.scope\n"
	outside = "0::/system.slice/containerd.service\n"
)

// cancelled runs a command that start lays out in /proc, cancels it once it's found, and returns
// the sweep's signals.
func cancelled(t *testing.T, start func(f *fake, marker string)) (stop, kill string) {
	t.Helper()
	r, f := runningSilo(t)
	r.ExecFind = 2 * time.Second
	initPID := f.pid
	proc(f, 50, 1, 50, outside)                        // the engine's shim
	proc(f, initPID, 50, initPID, inSilo, "PATH=/bin") // the silo's own init
	proc(f, 200, 50, 200, inSilo, "PATH=/bin")         // an exec that was there before
	started := make(chan struct{})
	f.execHook = func(ctx context.Context, c hostexec.Cmd) (int, error) {
		var marker string
		for i, a := range c.Args {
			if v, ok := strings.CutPrefix(a, kri.ExecMarkerEnv+"="); ok && c.Args[i-1] == "-e" {
				marker = v
			}
		}
		if marker == "" {
			t.Error("no marker in the exec's environment")
		}
		start(f, marker)
		close(started)
		<-ctx.Done() // the CLI is killed; the container's processes aren't
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
		t.Fatal("exec didn't return after its context was cancelled")
	}
	return f.last("kill -STOP"), f.last("kill -KILL")
}

// The client goes away mid-command: killing docker exec leaves the command running in the
// container, so the host sweeps it: what carries the exec's marker, and its session.
func TestExecCancelledKillsTheCommandInTheContainer(t *testing.T) {
	_, kill := cancelled(t, func(f *fake, m string) {
		proc(f, 4242, 50, 4242, inSilo, "PATH=/bin", kri.ExecMarkerEnv+"="+m, "HOME=/root")
		proc(f, 4243, 4242, 4242, inSilo, kri.ExecMarkerEnv+"="+m)
		proc(f, 77, 50, 77, inSilo, "PATH=/bin", kri.ExecMarkerEnv+"=someone-else")
	})
	if kill != "kill -KILL 4242 4243" {
		t.Fatalf("want both of its processes killed and nothing else, ran %q", kill)
	}
}

// `kvo exec -- env -i sh -c 'sleep 1000 & sleep 1000'`: nothing carries the marker by the time
// the client goes, but the host saw the exec's first process start: its whole session goes,
// including a child that left the tree (reparented to the silo's init).
func TestExecCancelledKillsACommandThatClearedItsEnvironment(t *testing.T) {
	stop, kill := cancelled(t, func(f *fake, _ string) {
		proc(f, 4300, 50, 4300, inSilo)         // env -i … : its environment is empty now
		proc(f, 4301, 4300, 4300, inSilo)       // sleep, its child
		proc(f, 4302, 100, 4300, inSilo)        // a background sleep, reparented to init
		proc(f, 4400, 100, 4400, inSilo, "A=b") // something the silo started itself (setsid)
		proc(f, 4500, 4499, 4500, outside, "")  // not in the silo at all
	})
	if kill != "kill -KILL 4300 4301 4302" {
		t.Fatalf("want the exec's session killed and nothing else, ran %q", kill)
	}
	if stop != "kill -STOP 4300 4301 4302" {
		t.Fatalf("want it stopped first, ran %q", stop)
	}
}

func TestExecFinishedKillsNothing(t *testing.T) {
	r, f := runningSilo(t)
	_ = f.WriteFile("/proc/9/environ", []byte(kri.ExecMarkerEnv+"=x\x00"), 0o644)
	if code, err := r.Exec(context.Background(), silo, kri.ExecRequest{Command: []string{"false"}}); code != 5 || err != nil {
		t.Fatalf("exec: %d %v", code, err)
	}
	if k := f.last("kill "); k != "" {
		t.Fatalf("a finished exec killed %q", k)
	}
}
