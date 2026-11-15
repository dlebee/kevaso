package agent_test

import (
	"context"
	"net/http/httptest"
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

func listed(t *testing.T, rt kri.Runtime, name string) bool {
	t.Helper()
	ids, err := rt.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.Name == name {
			return true
		}
	}
	return false
}

// K-004: a silo the API no longer lists, with no delete seen by this agent (a control plane
// restored from an older backup, a cluster made again), is kept with its disk and volumes; a
// delete the agent sees on its watch still removes it.
func TestASiloMissingFromTheAPIIsKeptUnlessItsDeleteWasSeen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer func() { cancel(); ts.Close() }()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := fake.New()
	e := &env{c: c, rt: rt, ctx: ctx}
	n := 0
	run := func() context.CancelFunc {
		actx, stop := context.WithCancel(ctx)
		n++
		who := n
		a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{},
			Log: func(f string, args ...any) { t.Logf("agent %d: "+f, append([]any{who}, args...)...) }}
		go a.Run(actx)
		return stop
	}

	// A delete made while no agent watches: the next agent finds the silo missing.
	stop := run()
	e.place(t, "db", "hv1", nil)
	e.wait(t, "db", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
	stop()
	time.Sleep(time.Second) // the first agent and its watch are gone
	if err := c.Delete(ctx, "Silo", "dev", "db"); err != nil {
		t.Fatal(err)
	}
	stop = run()
	time.Sleep(2 * time.Second)
	if !listed(t, rt, "db") {
		t.Fatal("a silo missing from the API, its delete never seen, was removed with its data")
	}

	// A delete this agent sees: removed.
	e.place(t, "tmp", "hv1", nil)
	e.wait(t, "tmp", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
	if err := c.Delete(ctx, "Silo", "dev", "tmp"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for listed(t, rt, "tmp") && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if listed(t, rt, "tmp") {
		t.Fatal("a delete the agent saw didn't remove the silo")
	}
	if !listed(t, rt, "db") {
		t.Fatal("the kept silo went away")
	}
	stop()
}
