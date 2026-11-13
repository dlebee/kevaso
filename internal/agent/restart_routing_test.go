package agent_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// startWatcher is a runtime that says, at each Start, whether the API routed the silo then.
type startWatcher struct {
	*fake.Runtime
	c        *client.Client
	mu       sync.Mutex
	routedAt []bool
}

func (w *startWatcher) Start(ctx context.Context, id kri.ID) error {
	var s v1.Silo
	if err := w.c.Get(ctx, "Silo", id.Namespace, id.Name, &s); err == nil {
		w.mu.Lock()
		w.routedAt = append(w.routedAt, routing.Routed(&s))
		w.mu.Unlock()
	}
	return w.Runtime.Start(ctx, id)
}

// Found by the restart audit; fixed on phase/metal (the Stopped/Created branch says NotRunning first).
//
// A silo with routeWhen: ready that stopped behind the agent's back (its VM died, the host
// rebooted, a liveness restart) is started again with its old Ready and Running still in its
// status: DNS, Service endpoints, host ports and ingress go on sending to it while it boots, before
// its readiness probe has passed since. The start must take it out of routing first.
func TestARestartedSiloIsNotRoutedBeforeItsReadinessPassesAgain(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := &startWatcher{Runtime: fake.New(), c: c}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports:   []v1.SiloPort{{Name: "web", Port: 8080}},
			Service: &v1.SiloService{RouteWhen: v1.RouteWhenReady, Ports: []v1.ServicePort{{Port: "web"}}},
			Probes:  &v1.Probes{Readiness: &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"true"}}, Period: "1s"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	for {
		if err := c.Get(ctx, "Silo", "dev", "web", &cur); err == nil && routing.Routed(&cur) && meta.IsTrue(cur.Status.Conditions, "Ready") {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("never routed: %+v", cur.Status)
		case <-time.After(20 * time.Millisecond):
		}
	}
	// Its VM stops behind the agent's back.
	if err := rt.Stop(ctx, kri.ID{Namespace: "dev", Name: "web", UID: cur.UID}); err != nil {
		t.Fatal(err)
	}
	touch(t, ctx, c, "dev", "web") // the agent looks again (as its 30s resync would)
	for {
		rt.mu.Lock()
		n := len(rt.routedAt)
		var routed bool
		if n >= 2 {
			routed = rt.routedAt[1]
		}
		rt.mu.Unlock()
		if n >= 2 {
			if routed {
				t.Fatal("started again while the API still routed traffic to it")
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("never started again")
		case <-time.After(20 * time.Millisecond):
		}
	}
}
