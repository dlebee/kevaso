package container

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// holdHost is the fake engine with an init container that runs as a real one does: `run --rm` of
// it returns only when its step ends (released), when it is killed, stopped or removed (137), or
// when its CLI is killed (the caller's context ends), which, as with a real engine, leaves the
// container running.
type holdHost struct {
	*fake
	mu      sync.Mutex // the fake's maps: the held run waits in another goroutine
	init    string     // the init container's name
	release chan struct{}
	killed  chan struct{}
	once    sync.Once
}

func newHoldHost(id kri.ID) *holdHost {
	return &holdHost{fake: newFake(), init: NamesFor(id).Init, release: make(chan struct{}), killed: make(chan struct{})}
}

func (h *holdHost) kill() { h.once.Do(func() { close(h.killed) }) }

func (h *holdHost) Run(ctx context.Context, c hostexec.Cmd) (int, error) {
	a := c.Args
	if (c.Name == "docker" || c.Name == "podman") && len(a) > 1 && a[0] == "run" && a[1] == "--rm" && a[indexOf(a, "--name")+1] == h.init {
		h.mu.Lock()
		h.cmds = append(h.cmds, c.Name+" "+strings.Join(a, " "))
		h.containers[h.init] = "running"
		h.mu.Unlock()
		select {
		case <-h.release:
			h.mu.Lock()
			delete(h.containers, h.init)
			h.mu.Unlock()
			return 0, nil
		case <-h.killed:
			return 137, nil
		case <-ctx.Done():
			return -1, ctx.Err() // the CLI is gone; the container runs on
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if (c.Name == "docker" || c.Name == "podman") && len(a) > 1 && a[len(a)-1] == h.init {
		switch a[0] {
		case "kill", "stop", "rm":
			if h.containers[h.init] == "running" {
				h.kill()
			}
			delete(h.containers, h.init) // --rm
			h.cmds = append(h.cmds, c.Name+" "+strings.Join(a, " "))
			return 0, nil
		}
	}
	return h.fake.Run(ctx, c)
}

func (h *holdHost) running(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.containers[name] == "running"
}

func (h *holdHost) ran(prefix string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// initSilo is a created silo (pause container running) whose init step runs now, held, on engine.
func initSilo(t *testing.T, engine string) (*Runtime, *holdHost, context.CancelFunc, chan int) {
	t.Helper()
	h := newHoldHost(silo)
	r := runtime(t, h.fake)
	r.Host, r.Engine = h, engine
	ctx := context.Background()
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	ictx, cancel := context.WithCancel(ctx)
	done := make(chan int, 1)
	go func() {
		code, _ := r.RunInit(ictx, silo, kri.InitStep{Name: "migrate", Run: "sleep 600"}, io.Discard)
		done <- code
	}()
	for deadline := time.Now().Add(5 * time.Second); !h.running(NamesFor(silo).Init); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the init container never ran")
		}
	}
	return r, h, cancel, done
}

func ended(t *testing.T, done chan int, want int) {
	t.Helper()
	select {
	case code := <-done:
		if code != want {
			t.Fatalf("the step exited %d, want %d", code, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the init step still runs")
	}
}

// K-088 (c): while an init step runs, the silo runs: Status says so (the fences ask Status
// whether anything of it still runs), and InitRunning says it is an init step.
func TestStatusSeesARunningInitStep(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		t.Run(engine, func(t *testing.T) {
			r, h, cancel, done := initSilo(t, engine)
			defer cancel()
			ctx := context.Background()
			st, err := r.Status(ctx, silo)
			if err != nil || st.State != kri.Running {
				t.Fatalf("an init step runs, Status says %s (%v)", st.State, err)
			}
			if running, err := r.InitRunning(ctx, silo); err != nil || !running {
				t.Fatalf("InitRunning: %v %v", running, err)
			}
			close(h.release)
			ended(t, done, 0)
			if st, _ := r.Status(ctx, silo); st.State == kri.Running {
				t.Fatalf("the step ended, nothing else was started: %s", st.State)
			}
			if running, _ := r.InitRunning(ctx, silo); running {
				t.Fatal("InitRunning after the step ended")
			}
		})
	}
}

// K-088 (c, d): Kill ends everything of the silo that can run code: its init container, its
// main container (exec'd commands are processes in it, and go with its PID 1), its pause
// container. Afterwards Status says nothing runs.
func TestKillEndsARunningInitStep(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		t.Run(engine, func(t *testing.T) {
			r, h, cancel, done := initSilo(t, engine)
			defer cancel()
			ctx := context.Background()
			if err := kri.Kill(ctx, r, silo); err != nil {
				t.Fatal(err)
			}
			ended(t, done, 137)
			n := NamesFor(silo)
			if h.running(n.Init) || h.running(n.Pause) {
				t.Fatalf("after a kill: init %v, pause %v", h.running(n.Init), h.running(n.Pause))
			}
			if !h.ran(engine + " kill --signal KILL " + n.Init) {
				t.Fatal("the init container wasn't killed (no grace for a fence)")
			}
			if st, err := r.Status(ctx, silo); err != nil || st.State == kri.Running {
				t.Fatalf("after a kill, Status: %s %v", st.State, err)
			}
		})
	}
}

// K-088 (c): Stop ends it too (a stop of a silo with no main process yet, a removal, a move).
func TestStopEndsARunningInitStep(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		t.Run(engine, func(t *testing.T) {
			r, h, cancel, done := initSilo(t, engine)
			defer cancel()
			ctx := context.Background()
			if err := r.Stop(ctx, silo); err != nil {
				t.Fatal(err)
			}
			ended(t, done, 137)
			n := NamesFor(silo)
			if h.running(n.Init) || h.running(n.Pause) {
				t.Fatalf("after a stop: init %v, pause %v", h.running(n.Init), h.running(n.Pause))
			}
			if st, _ := r.Status(ctx, silo); st.State == kri.Running {
				t.Fatalf("after a stop: %s", st.State)
			}
			// It starts again as before: the pause container comes back with its network.
			if err := r.Start(ctx, silo); err != nil {
				t.Fatal(err)
			}
			if st, _ := r.Status(ctx, silo); st.State != kri.Running || !h.running(n.Pause) {
				t.Fatalf("started again: %s, pause %v", st.State, h.running(n.Pause))
			}
		})
	}
}

// K-088 (b): a step whose caller goes away (its start ended: placed elsewhere, the fence) ends
// with it: killing the engine's CLI would leave the container running.
func TestAnInitStepWhoseCallerGoesAwayEnds(t *testing.T) {
	for _, engine := range []string{"docker", "podman"} {
		t.Run(engine, func(t *testing.T) {
			r, h, cancel, done := initSilo(t, engine)
			cancel()
			ended(t, done, -1)
			if h.running(NamesFor(silo).Init) {
				t.Fatal("the init container runs on after its caller went away")
			}
			if st, _ := r.Status(context.Background(), silo); st.State == kri.Running {
				t.Fatalf("Status: %s", st.State)
			}
		})
	}
}
