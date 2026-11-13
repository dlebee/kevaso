package agent_test

import (
	"context"
	"net/http/httptest"
	"slices"
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

type env struct {
	c   *client.Client
	rt  *fake.Runtime
	ctx context.Context
}

func setup(t *testing.T) *env {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := fake.New()
	rt.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		if strings.Contains(strings.Join(cmd, " "), "make it fail") {
			return "boom: the step broke", 7
		}
		return "", 0
	}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	return &env{c: c, rt: rt, ctx: ctx}
}

// place creates a silo already scheduled on host (what the scheduler would write).
func (e *env) place(t *testing.T, name, host string, init *v1.Init) {
	t.Helper()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, Init: init}}
	if err := e.c.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = host, "Scheduled"
	if err := e.c.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
}

func (e *env) wait(t *testing.T, name string, ok func(*v1.Silo) bool) *v1.Silo {
	t.Helper()
	for {
		var s v1.Silo
		if err := e.c.Get(e.ctx, "Silo", "dev", name, &s); err == nil && ok(&s) {
			return &s
		}
		select {
		case <-e.ctx.Done():
			var s v1.Silo
			_ = e.c.Get(context.Background(), "Silo", "dev", name, &s)
			t.Fatalf("%s never got there: %+v", name, s.Status)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRunsASiloAndItsInitStepsThenReady(t *testing.T) {
	e := setup(t)
	e.place(t, "web", "hv1", &v1.Init{Steps: []v1.InitStep{
		{Name: "tools", Run: "apt-get install -y git"},
		{Name: "check", Shell: "python3", Run: "print('ok')"},
	}})
	s := e.wait(t, "web", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
	if s.Status.Phase != agent.PhaseRunning || s.Status.Address == "" {
		t.Fatalf("status %+v", s.Status)
	}
	if len(s.Status.Init) != 2 || s.Status.Init[0].State != "Done" || s.Status.Init[1].State != "Done" {
		t.Fatalf("init %+v", s.Status.Init)
	}
	// The order the runtime saw: create, start, then nothing else needed.
	if !slices.Contains(e.rt.Calls, "create dev/web") || !slices.Contains(e.rt.Calls, "start dev/web") {
		t.Fatalf("runtime calls %v", e.rt.Calls)
	}
}

func TestAFailedStepStopsTheRestAndIsReported(t *testing.T) {
	e := setup(t)
	e.place(t, "bad", "hv1", &v1.Init{Steps: []v1.InitStep{
		{Name: "one", Run: "true"},
		{Name: "two", Run: "make it fail"},
		{Name: "three", Run: "never runs"},
	}})
	s := e.wait(t, "bad", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "InitFailed") })
	if meta.IsTrue(s.Status.Conditions, "Ready") {
		t.Fatal("a silo whose init failed is Ready")
	}
	c := meta.FindCondition(s.Status.Conditions, "InitFailed")
	if !strings.Contains(c.Message, "step two exited 7") || !strings.Contains(c.Message, "boom") {
		t.Fatalf("InitFailed message %q", c.Message)
	}
	for _, st := range s.Status.Init {
		if st.Name == "three" {
			t.Fatalf("a step after the failure ran: %+v", s.Status.Init)
		}
	}
}

func TestIgnoresSilosOnOtherHosts(t *testing.T) {
	e := setup(t)
	e.place(t, "elsewhere", "hv2", nil)
	e.place(t, "mine", "hv1", nil)
	e.wait(t, "mine", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
	if slices.Contains(e.rt.Calls, "create dev/elsewhere") {
		t.Fatal("the agent created a silo placed on another host")
	}
}

func TestDeletingASiloRemovesItFromTheRuntime(t *testing.T) {
	e := setup(t)
	e.place(t, "tmp", "hv1", nil)
	e.wait(t, "tmp", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
	if err := e.c.Delete(e.ctx, "Silo", "dev", "tmp"); err != nil {
		t.Fatal(err)
	}
	for {
		ids, _ := e.rt.List(e.ctx)
		if len(ids) == 0 {
			return
		}
		select {
		case <-e.ctx.Done():
			t.Fatalf("still in the runtime: %v", ids)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestCreateFailureIsReported(t *testing.T) {
	e := setup(t)
	e.rt.FailCreate["broken"] = errBoom
	e.place(t, "broken", "hv1", nil)
	s := e.wait(t, "broken", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseFailed })
	if c := meta.FindCondition(s.Status.Conditions, "Ready"); c == nil || c.Reason != "CreateFailed" {
		t.Fatalf("conditions %+v", s.Status.Conditions)
	}
}

type boom struct{}

func (boom) Error() string { return "disk full" }

var errBoom = boom{}

// Cut off from the control plane past FenceAfter, the agent stops what may be recreated elsewhere
// (onHostLoss: Recreate) and keeps Wait silos running.
func TestFencingWhenCutOff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := fake.New()
	rt.Handler = func(kri.ID, []string, []byte) (string, int) { return "", 0 }
	var mu sync.Mutex
	last := time.Now()
	contact := func() time.Time { mu.Lock(); defer mu.Unlock(); return last }
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{},
		LastContact: contact, FenceAfter: 300 * time.Millisecond}
	go a.Run(ctx)
	e := &env{c: c, rt: rt, ctx: ctx}
	for _, name := range []string{"stateless", "precious"} {
		e.place(t, name, "hv1", nil)
	}
	for { // the agent writes status meanwhile: retry on conflicts
		var s v1.Silo
		_ = c.Get(ctx, "Silo", "dev", "stateless", &s)
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		err := c.Update(ctx, &s)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"stateless", "precious"} {
		e.wait(t, name, func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	}
	state := func(name string) kri.State {
		var s v1.Silo
		_ = c.Get(ctx, "Silo", "dev", name, &s)
		st, _ := rt.Status(ctx, kri.ID{Namespace: "dev", Name: name, UID: s.UID})
		return st.State
	}
	keepContact := func() {
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}
	// Cut off.
	deadline := time.Now().Add(5 * time.Second)
	for state("stateless") != kri.Stopped {
		if time.Now().After(deadline) {
			t.Fatalf("the Recreate silo wasn't fenced: %s", state("stateless"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond) // and it stays stopped while cut off
	if got := state("stateless"); got != kri.Stopped {
		t.Fatalf("fenced silo restarted while cut off: %s", got)
	}
	if got := state("precious"); got != kri.Running {
		t.Fatalf("a Wait silo was stopped: %s", got)
	}
	// Contact again: it runs again (it wasn't recreated elsewhere).
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				keepContact()
			}
		}
	}()
	defer close(stop)
	deadline = time.Now().Add(10 * time.Second)
	for state("stateless") != kri.Running {
		if time.Now().After(deadline) {
			t.Fatalf("not restarted after contact came back: %s", state("stateless"))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A new image (resolved by the control plane) or a reset puts the silo back onto its image:
// stopped first, reset by the runtime, started again, the image it runs recorded.
func TestImageChangeAndResetAreStopFirst(t *testing.T) {
	e := setup(t)
	e.place(t, "node", "hv1", &v1.Init{Steps: []v1.InitStep{{Name: "setup", Run: "true"}}})
	s := e.wait(t, "node", func(s *v1.Silo) bool {
		return meta.IsTrue(s.Status.Conditions, "Ready") && s.Status.Image != nil && s.Status.Image.Running == "ubuntu-24.04"
	})
	id := kri.ID{Namespace: "dev", Name: "node", UID: s.UID}
	// The user moves it to geth:v2, which the control plane resolves.
	s.Spec.Image = "geth:v2"
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; ; attempt++ { // the agent writes the silo's status too (it saw the new spec)
		_ = e.c.Get(e.ctx, "Silo", "dev", "node", s)
		s.Status.Image = &v1.SiloImage{From: "geth:v2", Ref: "docker.io/ethereum/client-go:v1.15.0", Running: "ubuntu-24.04"}
		err := e.c.UpdateStatus(e.ctx, s)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || attempt > 20 {
			t.Fatal(err)
		}
	}
	s = e.wait(t, "node", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, "Ready")
		return s.Status.Image.Running == "docker.io/ethereum/client-go:v1.15.0" && c != nil && c.Status == meta.ConditionTrue && c.ObservedGeneration == s.Generation
	})
	if got := e.rt.Image(id); got != "docker.io/ethereum/client-go:v1.15.0" {
		t.Fatalf("the runtime has %q", got)
	}
	if len(s.Status.Init) != 1 || s.Status.Init[0].State != "Done" {
		t.Fatalf("init steps didn't run again on the fresh disk: %+v", s.Status.Init)
	}
	calls := strings.Join(e.rt.Calls, ",")
	if i, j := strings.LastIndex(calls, "stop dev/node"), strings.LastIndex(calls, "reset dev/node"); i < 0 || j < i {
		t.Fatalf("not stop-first: %s", calls)
	}
	// kvo reset: same image, a fresh copy.
	s.Spec.Reset = "2026-11-12T10:00:00Z"
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.wait(t, "node", func(s *v1.Silo) bool {
		return s.Status.Image.Reset == "2026-11-12T10:00:00Z" && meta.IsTrue(s.Status.Conditions, "Ready")
	})
	if n := strings.Count(strings.Join(e.rt.Calls, ","), "reset dev/node"); n != 2 {
		t.Fatalf("%d resets, want 2", n)
	}
}

// A readiness check keeps the silo from being Ready until it passes.
func TestReadiness(t *testing.T) {
	e := setup(t)
	var mu sync.Mutex
	synced := false
	e.rt.Handler = func(_ kri.ID, cmd []string, _ []byte) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(cmd, " ") == "check-synced" && !synced {
			return "still syncing", 1
		}
		return "", 0
	}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Readiness: &v1.Readiness{Command: []string{"check-synced"}, Period: "50ms"}}}
	if err := e.c.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := e.c.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	got := e.wait(t, "rpc", func(s *v1.Silo) bool {
		c := meta.FindCondition(s.Status.Conditions, "Ready")
		return c != nil && c.Reason == "NotReady"
	})
	if c := meta.FindCondition(got.Status.Conditions, "Ready"); !strings.Contains(c.Message, "still syncing") || got.Status.Phase != agent.PhaseRunning {
		t.Fatalf("not ready: %+v", got.Status)
	}
	mu.Lock()
	synced = true
	mu.Unlock()
	e.wait(t, "rpc", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
}

// A volume is kept data (design §0.3). A host that finds the old copy of a silo now placed on
// another host removes that copy, and with it (every runtime does, on Delete) its local volumes.
// Admission never lets a silo with a host-local volume be recreated elsewhere, so that copy should
// never hold one; if it does anyway (here: its status moved by hand), the host stops the copy and
// keeps it, volumes and all, until the silo is deleted. A copy without local volumes goes as before.
func TestOldCopyWithLocalVolumesIsKept(t *testing.T) {
	e := setup(t)
	mk := func(name string, vols []v1.Volume) *v1.Silo {
		t.Helper()
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, Volumes: vols}}
		if err := e.c.Create(e.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
		if err := e.c.UpdateStatus(e.ctx, s); err != nil {
			t.Fatal(err)
		}
		return e.wait(t, name, func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
	}
	keep := mk("keep", []v1.Volume{{Name: "db", MountPath: "/var/lib/db"}})
	plain := mk("plain", nil)
	for _, s := range []*v1.Silo{keep, plain} {
		s.Status.Host = "hv2" // recreated elsewhere, as the control plane would after losing hv1
		if err := e.c.UpdateStatus(e.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	has := func(name string) bool {
		ids, _ := e.rt.List(e.ctx)
		return slices.ContainsFunc(ids, func(id kri.ID) bool { return id.Name == name })
	}
	calls := func() []string { return slices.Clone(e.rt.Calls) }
	until := func(what string, ok func() bool) {
		t.Helper()
		for !ok() {
			select {
			case <-e.ctx.Done():
				t.Fatalf("%s: calls %v", what, calls())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	until("plain removed", func() bool { return !has("plain") })
	until("keep stopped", func() bool { return slices.Contains(calls(), "stop dev/keep") })
	time.Sleep(200 * time.Millisecond) // more reconciles: still kept
	if !has("keep") || slices.Contains(calls(), "delete dev/keep") {
		t.Fatalf("the copy with a local volume was removed: %v", calls())
	}
	if st, err := e.rt.Status(e.ctx, kri.ID{Namespace: "dev", Name: "keep", UID: keep.UID}); err != nil || st.State == kri.Running {
		t.Fatalf("kept copy still running: %+v %v", st, err)
	}
	// Deleting the silo removes it, volumes too.
	if err := e.c.Delete(e.ctx, "Silo", "dev", "keep"); err != nil {
		t.Fatal(err)
	}
	until("keep removed once deleted", func() bool { return !has("keep") })
}
