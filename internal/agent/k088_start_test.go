package agent_test

import (
	"context"
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
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// slowStart is the plain fake (no init containers: a VM's or an OpenShell sandbox's init steps run
// in it through Exec) whose Start takes as long as the test says: it returns once release is
// closed, or its context ends.
type slowStart struct {
	*fake.Runtime
	entered chan struct{}
	release chan struct{}
	ended   chan struct{} // closed when a Start returned because its context ended
	once    sync.Once
}

func newSlowStart() *slowStart {
	return &slowStart{Runtime: fake.New(), entered: make(chan struct{}), release: make(chan struct{}), ended: make(chan struct{})}
}

func (r *slowStart) Start(ctx context.Context, id kri.ID) error {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
	case <-ctx.Done():
		close(r.ended)
		return ctx.Err()
	}
	return r.Runtime.Start(ctx, id)
}

// claimRig is an agent on hv1 on a fake clock (its claim renewals, requeues and fence passes
// happen only when the test steps it), with the API served on the real clock.
type claimRig struct {
	t   *testing.T
	ctx context.Context
	c   *client.Client
	clk *clock.Fake
	a   *agent.Agent
	id  kri.ID
}

func newClaimRig(t *testing.T, rt kri.Runtime) *claimRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clk, Log: t.Logf}
	return &claimRig{t: t, ctx: ctx, c: c, clk: clk, a: a}
}

func (r *claimRig) place(steps ...v1.InitStep) {
	r.t.Helper()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if len(steps) > 0 {
		s.Spec.Init = &v1.Init{Steps: steps}
	}
	if err := r.c.Create(r.ctx, s); err != nil {
		r.t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := r.c.UpdateStatus(r.ctx, s); err != nil {
		r.t.Fatal(err)
	}
	r.id = kri.ID{Namespace: "dev", Name: "single", UID: s.UID}
}

func (r *claimRig) get() *v1.Silo {
	var cur v1.Silo
	if err := r.c.Get(r.ctx, "Silo", "dev", "single", &cur); err != nil {
		r.t.Fatal(err)
	}
	return &cur
}

// waitIn waits (real time) for ch, stepping the fake clock by a millisecond now and then so the
// agent's requeues happen.
func (r *claimRig) waitIn(what string, ch <-chan struct{}) {
	r.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		select {
		case <-ch:
			return
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("never: %s", what)
		}
		r.clk.Step(time.Millisecond)
	}
}

// renewed steps the fake clock a refresh at a time, four times, and says whether the stored
// claim was written anew (a new claim, hv1's) every time.
func (r *claimRig) renewedWhile(what string) {
	r.t.Helper()
	last := claimOf(r.get())
	if !strings.HasPrefix(last, "starting on hv1 at ") {
		r.t.Fatalf("no claim of hv1's while %s: %q", what, last)
	}
	for i := range 4 {
		r.clk.Step(agent.ClaimRefreshEvery)
		now := claimOf(r.get())
		if now == last || !strings.HasPrefix(now, "starting on hv1 at ") {
			r.t.Fatalf("%s for %s: the claim wasn't written anew (%q, then %q); the control plane counts it %s old and may start the silo elsewhere",
				what, time.Duration(i+1)*agent.ClaimRefreshEvery, last, now, time.Duration(i+1)*agent.ClaimRefreshEvery)
		}
		last = now
	}
}

// Review of K-088, claim 2: a Start that itself takes long (a VMM unit slow to come up, virtiofsd
// waits, a container engine that hangs) keeps the start claim fresh for as long as it runs.
func TestASlowStartKeepsItsStartClaimFresh(t *testing.T) {
	rt := newSlowStart()
	r := newClaimRig(t, rt)
	go r.a.Run(r.ctx)
	r.place()
	r.waitIn("the start begins", rt.entered)
	r.renewedWhile("a Start runs")
	close(rt.release)
}

// A renewal during a slow Start that finds the silo placed elsewhere ends the Start: nothing of
// it comes up here beside the new copy.
func TestAPlacementElsewhereDuringASlowStartEndsIt(t *testing.T) {
	rt := newSlowStart()
	r := newClaimRig(t, rt)
	go r.a.Run(r.ctx)
	r.place()
	r.waitIn("the start begins", rt.entered)
	for {
		cur := r.get()
		cur.Status.Host, cur.Status.Phase = "hv2", "Scheduled" // a person's --confirm-fenced move
		err := r.c.UpdateStatus(r.ctx, cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	r.clk.Step(agent.ClaimRefreshEvery)
	select {
	case <-rt.ended:
	case <-time.After(5 * time.Second):
		close(rt.release) // the old way: the Start runs to its end
		time.Sleep(100 * time.Millisecond)
		t.Fatalf("the Start went on after a renewal found the silo placed elsewhere: %v", rt.CallLog())
	}
	for _, c := range rt.CallLog() {
		if strings.HasPrefix(c, "start ") {
			t.Fatalf("started on hv1 after it was placed elsewhere: %v", rt.CallLog())
		}
	}
}

// Review of K-088, claim 2: a VM's or an OpenShell sandbox's init steps run in it through Exec,
// after its start; the claim stays fresh through them, until the silo is reported Running, and
// renewals end then.
func TestASlowGuestInitStepKeepsItsStartClaimFresh(t *testing.T) {
	rt := fake.New()
	inStep, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	rt.Program = func(ctx context.Context, _ kri.ID, req kri.ExecRequest) int {
		if !strings.Contains(strings.Join(req.Command, " "), "sleep 600") {
			return 0
		}
		once.Do(func() { close(inStep) })
		select {
		case <-release:
			return 0
		case <-ctx.Done():
			return -1
		}
	}
	r := newClaimRig(t, rt)
	go r.a.Run(r.ctx)
	r.place(v1.InitStep{Name: "slow", Run: "sleep 600"})
	r.waitIn("the guest's init step runs", inStep)
	r.renewedWhile("a guest init step runs")
	close(release)
	running := make(chan struct{})
	go func() {
		for r.ctx.Err() == nil {
			if r.get().Status.Phase == agent.PhaseRunning {
				close(running)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	r.waitIn("the silo is reported Running", running)
	last := claimOf(r.get())
	for range 3 {
		r.clk.Step(agent.ClaimRefreshEvery)
	}
	if now := claimOf(r.get()); now != last {
		t.Fatalf("the claim is still renewed once the silo is reported Running: %q then %q", last, now)
	}
}
