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

// A restored history (epoch above 1) does not start a silo this worker is not already running.
// Once the control plane marks that silo settled for the history, it starts.
func TestARestoredHistoryDoesNotStartACopyItIsNotAlreadyRunning(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	cp := &cpHeaders{h: srv, seen: client.ControlPlaneSeen{ClusterID: "c1", History: "h2", Epoch: 2, Revision: 10}}
	ts := httptest.NewServer(cp)
	t.Cleanup(ts.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	rt := fake.New()
	cl := client.New(ts.URL)
	a := &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}, Log: t.Logf}
	cl.ControlPlane = a.ControlPlaneJudge()
	agent.RunForTest(t, ctx, a)
	e := &env{c: c, rt: rt, ctx: ctx}
	e.place(t, "web", "hv1", nil)

	absent := func() bool {
		ids, _ := rt.List(ctx)
		for _, id := range ids {
			if id.Name == "web" {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !absent() {
			t.Fatal("a restored history started a silo before it was settled")
		}
		time.Sleep(50 * time.Millisecond)
	}

	var s v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "web", &s); err != nil {
		t.Fatal(err)
	}
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreSettled}
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}
	e.wait(t, "web", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
	if absent() {
		t.Fatal("a settled silo was not started")
	}
}
