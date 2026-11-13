package container

import (
	"context"
	"errors"
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

// The client goes away mid-command: killing docker exec leaves the command running in the
// container, so everything carrying the exec's marker is killed from the host.
func TestExecCancelledKillsTheCommandInTheContainer(t *testing.T) {
	r, f := runningSilo(t)
	started := make(chan string, 1)
	f.execHook = func(ctx context.Context, c hostexec.Cmd) (int, error) {
		var marker string
		for i, a := range c.Args {
			if v, ok := strings.CutPrefix(a, kri.ExecMarkerEnv+"="); ok && c.Args[i-1] == "-e" {
				marker = v
			}
		}
		// What the host's /proc shows: the command and a child it started, and an unrelated process.
		f.files["/proc/4242/environ"] = []byte("PATH=/bin\x00" + kri.ExecMarkerEnv + "=" + marker + "\x00HOME=/root\x00")
		f.files["/proc/4243/environ"] = []byte(kri.ExecMarkerEnv + "=" + marker + "\x00")
		f.files["/proc/77/environ"] = []byte("PATH=/bin\x00" + kri.ExecMarkerEnv + "=someone-else\x00")
		started <- marker
		<-ctx.Done() // the CLI is killed; the container's processes aren't
		return -1, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"sleep", "1000"}})
		errc <- err
	}()
	if m := <-started; m == "" {
		t.Fatal("no marker in the exec's environment")
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("exec returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec didn't return after its context was cancelled")
	}
	kill := f.last("kill ")
	if kill != "kill -KILL 4242 4243" && kill != "kill -KILL 4243 4242" {
		t.Fatalf("want both marked processes killed and nothing else, ran %q", kill)
	}
}

func TestExecFinishedKillsNothing(t *testing.T) {
	r, f := runningSilo(t)
	f.files["/proc/9/environ"] = []byte(kri.ExecMarkerEnv + "=x\x00")
	if code, err := r.Exec(context.Background(), silo, kri.ExecRequest{Command: []string{"false"}}); code != 5 || err != nil {
		t.Fatalf("exec: %d %v", code, err)
	}
	if k := f.last("kill "); k != "" {
		t.Fatalf("a finished exec killed %q", k)
	}
}
