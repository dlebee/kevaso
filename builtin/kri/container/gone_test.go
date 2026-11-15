package container

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// stuckHost is the fake engine whose main container is left in one state, with one process id,
// whatever is done to it (a kill that doesn't take: podman's "stopping", docker's "removing", a
// frozen "paused" one, a process the engine still reports).
type stuckHost struct {
	*fake
	main  string
	state string
	pid   int
}

func (h *stuckHost) Run(ctx context.Context, c hostexec.Cmd) (int, error) {
	a := c.Args
	if (c.Name == "docker" || c.Name == "podman") && len(a) > 1 && a[0] == "container" && a[1] == "inspect" && a[len(a)-1] == h.main {
		h.cmds = append(h.cmds, c.Name+" "+strings.Join(a, " "))
		if c.Stdout != nil {
			_, _ = io.WriteString(c.Stdout, fmt.Sprintf("%s %d", h.state, h.pid))
		}
		return 0, nil
	}
	return h.fake.Run(ctx, c)
}

// Stopped means nothing of the silo runs (review of K-094, claim 1, the container runtime's
// equivalent): a main container in a state between running and gone, or one the engine still
// gives a process, is not killed yet and is Running, whether its state file is readable or not.
func TestAContainerThatHasNotGoneIsNeverStopped(t *testing.T) {
	cases := []struct {
		state string
		pid   int
	}{
		{"stopping", 4242}, // podman, while a stop or kill is under way
		{"removing", 4242}, // docker
		{"paused", 4242},   // frozen, not gone
		{"restarting", 0},  // the engine brings it back
		{"exited", 4242},   // the engine says exited, and still gives it a process
		{"something", 0},   // a state this runtime doesn't know
	}
	for _, engine := range []string{"docker", "podman"} {
		for _, tc := range cases {
			for _, readable := range []bool{true, false} {
				name := fmt.Sprintf("%s/%s-pid%d", engine, tc.state, tc.pid)
				if !readable {
					name += "/unreadable"
				}
				t.Run(name, func(t *testing.T) {
					ctx := context.Background()
					f := newFake()
					r := runtime(t, f)
					r.Engine = engine
					if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
						t.Fatal(err)
					}
					if err := r.Start(ctx, silo); err != nil {
						t.Fatal(err)
					}
					r.Host = &stuckHost{fake: f, main: NamesFor(silo).Main, state: tc.state, pid: tc.pid}
					if !readable {
						f.files[statePath(silo)] = []byte("{\"id\": ")
					}
					if err := r.Kill(ctx, silo); err == nil {
						t.Fatalf("Kill said done while the main container is %s (pid %d)", tc.state, tc.pid)
					}
					st, err := r.Status(ctx, silo)
					if err != nil || st.State != kri.Running {
						t.Fatalf("Status %s %v while the main container is %s (pid %d): a fence counts it stopped", st.State, err, tc.state, tc.pid)
					}
				})
			}
		}
	}
}

// A main container that runs while its pause container doesn't still runs the silo's code.
func TestAMainContainerWithoutItsPauseContainerIsRunning(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	f.containers[NamesFor(silo).Pause] = "exited"
	if st, err := r.Status(ctx, silo); err != nil || st.State != kri.Running {
		t.Fatalf("Status %s %v: its main container runs", st.State, err)
	}
}

// Review claim 3: the agent's reset gate is asked inside Reset, right before the containers go;
// a gate that refuses removes nothing.
func TestResetAsksItsGateBeforeRemovingAnything(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	refused := fmt.Errorf("taken back")
	before := len(f.cmds)
	if err := r.ResetGated(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}, func(context.Context) error { return refused }); err != refused {
		t.Fatalf("ResetGated: %v, want the gate's error", err)
	}
	for _, c := range f.cmds[before:] {
		if strings.Contains(c, " rm ") {
			t.Fatalf("removed although the gate refused: %v", f.cmds[before:])
		}
	}
	if _, ok := f.containers[NamesFor(silo).Main]; !ok {
		t.Fatal("the main container is gone although the gate refused")
	}
}
