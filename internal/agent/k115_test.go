package agent_test

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// alwaysFails is the strict fake as a container runtime whose Start always fails (the engine refuses
// to run the image), or whose init step exits 3, counting the tries.
type alwaysFails struct {
	*fake.Strict
	failStart bool
	starts    atomic.Int32
	inits     atomic.Int32
}

func (r *alwaysFails) Start(ctx context.Context, id kri.ID) error {
	r.starts.Add(1)
	if r.failStart {
		return errors.New("docker run: exit 125: OCI runtime create failed")
	}
	return r.Strict.Start(ctx, id)
}

func (r *alwaysFails) RunInit(ctx context.Context, id kri.ID, step kri.InitStep, out io.Writer) (int, error) {
	r.inits.Add(1)
	if _, err := r.Strict.RunInit(ctx, id, step, out); err != nil {
		return -1, err
	}
	return 3, nil
}

// newK115 is an agent on hv1 on a fake clock, its API served through a hook counting start
// claims, with one container silo placed on it (steps as given).
func newK115(t *testing.T, rt kri.Runtime, steps ...v1.InitStep) (*claimHook, *clock.Fake, func() *v1.Silo) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	hook := &claimHook{h: srv}
	ts := httptest.NewServer(hook)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clk}
	agent.RunForTest(t, ctx, a)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "broken", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if len(steps) > 0 {
		s.Spec.Init = &v1.Init{Steps: steps}
	}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	get := func() *v1.Silo {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", "dev", "broken", &cur); err != nil {
			t.Fatal(err)
		}
		return &cur
	}
	return hook, clk, get
}

func waitReal(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
	}
}

// K-115: a start that always fails is tried again only after a backoff on the agent's clock, and
// writes no start claim meanwhile: the claim's own event (and every other status write of the
// agent's) used to cancel the queue's backoff, so the silo was claimed and started again at once,
// thousands of times a second.
func TestAStartThatAlwaysFailsWaitsOutItsBackoffWithNoClaim(t *testing.T) {
	rt := &alwaysFails{Strict: fake.NewStrict("hv1", nil), failStart: true}
	hook, clk, _ := newK115(t, rt)
	waitReal(t, "a start is tried", func() bool { return rt.starts.Load() > 0 })
	time.Sleep(50 * time.Millisecond) // its writes after the failure come back as events
	c0, s0 := hook.claims.Load(), rt.starts.Load()
	time.Sleep(500 * time.Millisecond) // the agent's clock doesn't move: no backoff ends
	if c, s := hook.claims.Load()-c0, rt.starts.Load()-s0; c > 0 || s > 0 {
		t.Fatalf("with no time gone by on the agent's clock, %d start claims were written and %d starts tried", c, s)
	}
	// Ten minutes on the agent's clock: tried again, each after a longer wait (5s doubling to 5m).
	for range 600 {
		clk.Step(time.Second)
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := rt.starts.Load() - s0; n < 2 || n > 10 {
		t.Fatalf("%d starts tried in ten minutes of the agent's clock: want a few, spaced by a backoff", n)
	}
	// Per try: the claim, the claim again right before the start, and the status write saying the
	// start failed (the hook counts every status write that carries the stored claim).
	if c := hook.claims.Load() - c0; c > 3*(rt.starts.Load()-s0)+2 {
		t.Fatalf("%d start claims for %d starts", c, rt.starts.Load()-s0)
	}
}

// The same for an init step that failed: it stays failed (until the silo is reset or its spec
// changes), and nothing claims a start that can't go on.
func TestAFailedInitStepWritesNoMoreClaims(t *testing.T) {
	rt := &alwaysFails{Strict: fake.NewStrict("hv1", nil)}
	hook, clk, get := newK115(t, rt, v1.InitStep{Name: "migrate", Run: "exit 3"})
	waitReal(t, "InitFailed", func() bool {
		c := meta.FindCondition(get().Status.Conditions, "InitFailed")
		return c != nil && c.Status == meta.ConditionTrue
	})
	time.Sleep(50 * time.Millisecond)
	c0, i0 := hook.claims.Load(), rt.inits.Load()
	time.Sleep(500 * time.Millisecond)
	for range 100 {
		clk.Step(time.Second)
		time.Sleep(2 * time.Millisecond)
	}
	if c, i := hook.claims.Load()-c0, rt.inits.Load()-i0; c > 0 || i > 0 {
		t.Fatalf("after its init step failed: %d start claims written, the step run %d more times", c, i)
	}
	if n := rt.starts.Load(); n != 0 {
		t.Fatalf("the main process was started %d times after a failed init step", n)
	}
}

// exitsAtOnce is the strict fake as an engine whose Start succeeds and whose main process then
// ends at once (a command that isn't there: docker run -d returns, the container exits 127, and
// the silo reads Stopped): what the machines saw (TestMetal2StartBackoffNoClaim).
type exitsAtOnce struct {
	*fake.Strict
	starts atomic.Int32
}

func (r *exitsAtOnce) Start(ctx context.Context, id kri.ID) error {
	r.starts.Add(1)
	if err := r.Strict.Start(ctx, id); err != nil {
		return err
	}
	return r.Stop(ctx, id) // it exited by itself
}

// exitsAtOnceVM is exitsAtOnce as a VM runtime (no init containers): a VMM that exits right
// after it started.
type exitsAtOnceVM struct{ r *exitsAtOnce }

func (v exitsAtOnceVM) Info() kri.Info                                  { return v.r.Info() }
func (v exitsAtOnceVM) Create(ctx context.Context, spec kri.Spec) error { return v.r.Create(ctx, spec) }
func (v exitsAtOnceVM) Start(ctx context.Context, id kri.ID) error      { return v.r.Start(ctx, id) }
func (v exitsAtOnceVM) Stop(ctx context.Context, id kri.ID) error       { return v.r.Stop(ctx, id) }
func (v exitsAtOnceVM) Delete(ctx context.Context, id kri.ID) error     { return v.r.Delete(ctx, id) }
func (v exitsAtOnceVM) List(ctx context.Context) ([]kri.ID, error)      { return v.r.List(ctx) }
func (v exitsAtOnceVM) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	return v.r.Status(ctx, id)
}
func (v exitsAtOnceVM) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	return v.r.Exec(ctx, id, req)
}

// K-115 as the machines saw it: a start that succeeds and whose silo stops by itself at once is
// a failed start too. It is tried again only after the backoff, with no claim meanwhile.
func TestASiloThatExitsRightAfterItsStartWaitsOutItsBackoffWithNoClaim(t *testing.T) {
	for _, vm := range []bool{false, true} {
		t.Run(map[bool]string{true: "vm", false: "container"}[vm], func(t *testing.T) {
			r := &exitsAtOnce{Strict: fake.NewStrict("hv1", nil)}
			var rt kri.Runtime = r
			if vm {
				rt = exitsAtOnceVM{r}
			}
			hook, clk, get := newK115(t, rt)
			waitReal(t, "a start is tried", func() bool { return r.starts.Load() > 0 })
			time.Sleep(50 * time.Millisecond)
			c0, s0 := hook.claims.Load(), r.starts.Load()
			time.Sleep(500 * time.Millisecond) // the agent's clock doesn't move
			if c, s := hook.claims.Load()-c0, r.starts.Load()-s0; c > 0 || s > 0 {
				t.Fatalf("with no time gone by on the agent's clock, %d start claims were written and %d starts tried", c, s)
			}
			if ready := meta.FindCondition(get().Status.Conditions, "Ready"); ready == nil || !strings.Contains(ready.Message, "trying again in") {
				t.Fatalf("Ready doesn't say it waits: %+v", ready)
			}
			for range 600 {
				clk.Step(time.Second)
				time.Sleep(2 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
			if n := r.starts.Load() - s0; n < 2 || n > 10 {
				t.Fatalf("%d starts tried in ten minutes of the agent's clock: want a few, spaced by a backoff", n)
			}
		})
	}
}
