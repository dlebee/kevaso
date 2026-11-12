package agent_test

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
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
