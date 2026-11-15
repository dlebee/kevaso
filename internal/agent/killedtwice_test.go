package agent_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/probes"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// dying is the strict fake whose silos' main process can be killed from outside, as the machines
// did (systemctl kill -s KILL --kill-whom=main of a VMM's unit): from then on, and until its next
// Start, Status says Failed, as cloud-hypervisor and the container runtime do. Exec can be made to
// hang (wedge) the way cloud-hypervisor's did on a guest that doesn't answer: until its context
// ends, whether or not the silo still runs (its wait for the guest's SSH, and an SSH session to a
// guest whose VMM is gone, never end by themselves).
type dying struct {
	*fake.Strict
	clk *clock.Fake

	mu     sync.Mutex
	failed map[string]bool // uid → killed since its last start
	starts []time.Time     // the agent's clock at each Start
	// wedge, if set, says whether an Exec of cmd during the silo's start number n (1: its first)
	// hangs until its context ends.
	wedge func(n int, cmd string) bool
	// killAtStart, if > 0, kills the main process as Start number killAtStart returns (a VMM
	// killed right as it came up, its claim held).
	killAtStart int
	wedged      chan string // a wedged Exec began (its command)
}

func newDying(clk *clock.Fake) *dying {
	d := &dying{Strict: fake.NewStrict("hv1", nil), clk: clk, failed: map[string]bool{}, wedged: make(chan string, 16)}
	d.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		if strings.Contains(strings.Join(cmd, " "), "echod") && !strings.Contains(strings.Join(cmd, " "), "setsid") {
			return "running\n", 0 // the daemon's probe: it runs
		}
		return "", 0
	}
	return d
}

func (d *dying) Start(ctx context.Context, id kri.ID) error {
	if err := d.Strict.Start(ctx, id); err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.failed, id.UID)
	d.starts = append(d.starts, d.clk.Now())
	kill := d.killAtStart == len(d.starts)
	d.mu.Unlock()
	if kill {
		d.kill(id)
	}
	return nil
}

// kill kills the silo's main process: Failed from now on.
func (d *dying) kill(id kri.ID) {
	d.mu.Lock()
	d.failed[id.UID] = true
	d.mu.Unlock()
	_ = d.Kill(context.Background(), id)
}

func (d *dying) Stop(ctx context.Context, id kri.ID) error {
	err := d.Strict.Stop(ctx, id)
	d.mu.Lock()
	delete(d.failed, id.UID)
	d.mu.Unlock()
	return err
}

func (d *dying) Delete(ctx context.Context, id kri.ID) error {
	d.mu.Lock()
	delete(d.failed, id.UID)
	d.mu.Unlock()
	return d.Strict.Delete(ctx, id)
}

func (d *dying) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	st, err := d.Strict.Status(ctx, id)
	d.mu.Lock()
	failed := d.failed[id.UID]
	d.mu.Unlock()
	if err == nil && failed && st.State != kri.Absent {
		return kri.Status{State: kri.Failed, Message: "Main process exited, code=killed, status=9/KILL"}, nil
	}
	return st, err
}

func (d *dying) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	cmd := strings.Join(req.Command, " ")
	d.mu.Lock()
	n, wedge := len(d.starts), d.wedge
	d.mu.Unlock()
	if wedge == nil || !wedge(n, cmd) {
		return d.Strict.Exec(ctx, id, req)
	}
	if st, err := d.Status(ctx, id); err != nil || st.State != kri.Running {
		return -1, fmt.Errorf("%s is not running", id)
	}
	select {
	case d.wedged <- cmd:
	default:
	}
	<-ctx.Done() // the guest never answers, and nothing here looks whether it still runs
	return -1, ctx.Err()
}

func (d *dying) setWedge(f func(n int, cmd string) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wedge = f
}

func (d *dying) startTimes() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.starts...)
}

// vmLike is dying as a VM runtime (cloud-hypervisor): no init containers and no host-written
// secrets, so its init steps and its daemons run in it through Exec.
type vmLike struct{ d *dying }

func (v vmLike) Info() kri.Info                                  { return v.d.Info() }
func (v vmLike) Create(ctx context.Context, spec kri.Spec) error { return v.d.Create(ctx, spec) }
func (v vmLike) Start(ctx context.Context, id kri.ID) error      { return v.d.Start(ctx, id) }
func (v vmLike) Stop(ctx context.Context, id kri.ID) error       { return v.d.Stop(ctx, id) }
func (v vmLike) Kill(ctx context.Context, id kri.ID) error       { return v.d.Kill(ctx, id) }
func (v vmLike) Delete(ctx context.Context, id kri.ID) error     { return v.d.Delete(ctx, id) }
func (v vmLike) List(ctx context.Context) ([]kri.ID, error)      { return v.d.List(ctx) }
func (v vmLike) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	return v.d.Status(ctx, id)
}

func (v vmLike) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	return v.d.Exec(ctx, id, req)
}

// twice is an agent on hv1 on a fake clock with one silo, an init step run at every boot and a
// daemon, on d as a VM runtime or as a container runtime.
type twice struct {
	t   *testing.T
	ctx context.Context
	c   *client.Client
	clk *clock.Fake
	d   *dying
	id  kri.ID
}

const bootStep = "echo booted"

func newTwice(t *testing.T, vm bool) *twice {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	d := newDying(clk)
	var rt kri.Runtime = d
	if vm {
		rt = vmLike{d}
	}
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clk, Log: t.Logf}
	agent.RunForTest(t, ctx, a)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "vm", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Init:    &v1.Init{When: "everyBoot", Steps: []v1.InitStep{{Name: "boot", Run: bootStep}}},
			Daemons: []v1.Daemon{{Name: "echod", Run: "sleep infinity"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	return &twice{t: t, ctx: ctx, c: c, clk: clk, d: d, id: kri.ID{Namespace: "dev", Name: "vm", UID: s.UID}}
}

func (w *twice) get() *v1.Silo {
	var cur v1.Silo
	if err := w.c.Get(w.ctx, "Silo", "dev", "vm", &cur); err != nil {
		w.t.Fatal(err)
	}
	return &cur
}

func (w *twice) ready() *meta.Condition {
	return meta.FindCondition(w.get().Status.Conditions, "Ready")
}

// until steps the agent's clock by step until cond holds (20s of real time at most): requeues,
// resyncs and the agent's looks happen only as the clock moves. A step of 0 doesn't move it.
func (w *twice) until(what string, step time.Duration, cond func() bool) {
	w.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			w.t.Fatalf("never (%s of the agent's clock went by): %s; Ready is %+v", w.clk.Now().Sub(time.Unix(1_000_000, 0)), what, w.ready())
		}
		time.Sleep(5 * time.Millisecond)
		if step > 0 {
			w.clk.Step(step)
		}
	}
}

func (w *twice) runningReported() bool {
	c := w.ready()
	return c != nil && c.Status == meta.ConditionTrue && w.get().Status.Phase == agent.PhaseRunning
}

func (w *twice) waitingOutBackoff() bool {
	c := w.ready()
	return c != nil && c.Reason == "RuntimeFailed" && strings.Contains(c.Message, "starting it again in")
}

func (w *twice) wedgedIn(what string) string {
	w.t.Helper()
	var got string
	w.until("a command in the silo hangs ("+what+")", 100*time.Millisecond, func() bool {
		select {
		case got = <-w.d.wedged:
			return true
		default:
			return false
		}
	})
	return got
}

// The first kill, and its restart (restart 1) reported Running.
func (w *twice) firstKill() *v1.LivenessRestarts {
	w.t.Helper()
	w.until("the silo is reported Running", 100*time.Millisecond, w.runningReported)
	w.d.kill(w.id)
	w.until("the first kill is noticed and the silo started again", 100*time.Millisecond, func() bool {
		r := w.get().Status.Restarts
		return r != nil && r.Count == 1 && len(w.d.startTimes()) >= 2
	})
	return w.get().Status.Restarts
}

// The second kill was noticed: Ready doesn't say it runs, the restart waits out the documented
// backoff (probes.RestartWait), and no start claim stands for it meanwhile.
func (w *twice) secondKillNoticed() {
	w.t.Helper()
	w.until("the second kill is noticed (Ready says it starts again after its backoff)", 100*time.Millisecond, w.waitingOutBackoff)
	if c := w.ready(); c.Status == meta.ConditionTrue || w.get().Status.Phase == agent.PhaseRunning {
		w.t.Fatalf("a silo that doesn't run is reported running: %+v", c)
	}
	if n := len(w.d.startTimes()); n != 2 {
		w.t.Fatalf("started %d times before its backoff was over", n)
	}
	if got := claimOf(w.get()); got != "" && strings.Contains(w.ready().Message, "starting it again in") {
		// A claim written during the start that failed may still be stored; it must not be renewed.
		last := got
		w.clk.Step(time.Second)
		time.Sleep(50 * time.Millisecond)
		if now := claimOf(w.get()); now != last && now != "" {
			w.t.Fatalf("its start claim is renewed while it waits out its backoff: %q, then %q", last, now)
		}
	}
}

func (w *twice) restartedAfterBackoff(r1 *v1.LivenessRestarts) {
	w.t.Helper()
	w.until("started again after its backoff (restart 2)", 500*time.Millisecond, func() bool { return len(w.d.startTimes()) >= 3 })
	third := w.d.startTimes()[2]
	if earliest := r1.Last.Add(probes.Backoff(r1.Backoff)); third.Before(earliest) {
		w.t.Fatalf("restart 2 at %s, before its backoff ended (%s)", third, earliest)
	}
	w.until("restart 2 is recorded", 100*time.Millisecond, func() bool { r := w.get().Status.Restarts; return r != nil && r.Count == 2 })
}

func (w *twice) deleteIsProcessed(what string) {
	w.t.Helper()
	if err := w.c.Delete(w.ctx, "Silo", "dev", "vm"); err != nil {
		w.t.Fatal(err)
	}
	// The clock moves by a millisecond at a time only: nothing waits out a backoff or a resync.
	w.until("the delete is processed "+what+": the copy removed", time.Millisecond, func() bool { return !holds(w.t, w.d, w.id.UID) })
}

// Found on the machines three times (metal.md, TestMetal2BackoffHoldsNoClaim): a microVM whose VMM
// is killed twice is no longer reconciled. The second kill came while the agent ran a command in
// the restarted guest (its daemon's probe, right after it was reported Running): that Exec never
// returned (cloud-hypervisor's waited for the guest's SSH for ever, and nothing looked whether
// the silo still ran), so the failure wasn't noticed, Ready kept saying Running, nothing restarted
// it, and its delete was never processed. The same for a container silo.
func TestASiloKilledAgainWhileACommandRunsInItIsNoticedRestartedAndDeletable(t *testing.T) {
	for _, vm := range []bool{true, false} {
		t.Run(map[bool]string{true: "vm", false: "container"}[vm], func(t *testing.T) {
			w := newTwice(t, vm)
			w.d.setWedge(func(n int, cmd string) bool { return n >= 2 && strings.Contains(cmd, "echod") }) // the restarted guest doesn't answer
			r1 := w.firstKill()
			w.wedgedIn("the daemon's probe in the restarted silo")
			if !w.runningReported() {
				t.Fatalf("restart 1 wasn't reported Running before its daemon was looked at: %+v", w.ready())
			}
			w.d.kill(w.id) // the second kill, while that command hangs
			w.secondKillNoticed()
			w.restartedAfterBackoff(r1)
			w.wedgedIn("the daemon's probe after restart 2")
			w.deleteIsProcessed("while a command in it hangs (the silo runs)")
		})
	}
}

// The same, the second kill during the restart's start, its claim held: a VM's init step run in
// it at every boot (it hangs: the guest doesn't answer), or a container killed as its start
// returns. Its delete is processed while it waits out its backoff.
func TestASiloKilledAgainDuringItsRestartIsNoticedAndDeletableInItsBackoff(t *testing.T) {
	t.Run("vm", func(t *testing.T) {
		// Its init step hangs at its first two starts (the guest doesn't answer), and is killed
		// during each: not recorded, it runs again at the next start.
		w := newTwice(t, true)
		w.d.setWedge(func(n int, cmd string) bool { return n <= 2 && strings.Contains(cmd, bootStep) })
		w.wedgedIn("the init step of its first start")
		w.d.kill(w.id)
		w.until("the first kill is noticed and the silo started again", 100*time.Millisecond, func() bool {
			r := w.get().Status.Restarts
			return r != nil && r.Count == 1 && len(w.d.startTimes()) >= 2
		})
		w.wedgedIn("the init step of restart 1")
		if claimOf(w.get()) == "" {
			t.Fatal("no start claim while restart 1's init step runs: the test shows nothing")
		}
		w.d.kill(w.id)
		w.secondKillNoticed()
		w.deleteIsProcessed("while it waits out its backoff")
		if n := len(w.d.startTimes()); n != 2 {
			t.Fatalf("started again after its delete: %d starts", n)
		}
	})
	t.Run("container", func(t *testing.T) {
		w := newTwice(t, false)
		w.d.mu.Lock()
		w.d.killAtStart = 2
		w.d.mu.Unlock()
		r1 := w.firstKill()
		w.secondKillNoticed()
		w.restartedAfterBackoff(r1)
		w.until("restart 2 reported Running", 100*time.Millisecond, w.runningReported)
		w.deleteIsProcessed("once it runs")
	})
}

// hangingPull is the strict fake as a runtime that pulls images itself, whose pull hangs until its
// context ends (a registry that never answers).
type hangingPull struct {
	*fake.Strict
	entered, ended chan struct{}
}

func (h *hangingPull) Pull(ctx context.Context, _ kri.ID, _ string, _ *kri.RegistryAuth) (string, error) {
	close(h.entered)
	<-ctx.Done()
	close(h.ended)
	return "", ctx.Err()
}

// Every reconcile of a silo placed here ends when its delete is seen, whatever it waits on: here a
// pull that hangs (no start claim, no command inside it yet, nothing else that would end it).
func TestADeleteEndsAPullThatHangs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := &hangingPull{Strict: fake.NewStrict("hv1", nil), entered: make(chan struct{}), ended: make(chan struct{})}
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	agent.RunForTest(t, ctx, a)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "big", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "registry.example/big:1"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rt.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("never pulled")
	}
	if err := c.Delete(ctx, "Silo", "dev", "big"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-rt.ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the delete didn't end the pull that hangs: the silo's reconcile waits on it for ever")
	}
}
