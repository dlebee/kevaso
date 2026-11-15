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
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// duringStop is the plain fake whose Stop runs during (a person changing the spec while the VM
// powers off: cloud-hypervisor waits up to 30s for it).
type duringStop struct {
	*fake.Runtime
	during func()
	mu     sync.Mutex
	resets []string // the image of each Reset
}

func (r *duringStop) Reset(ctx context.Context, spec kri.Spec) error {
	r.mu.Lock()
	r.resets = append(r.resets, spec.Image)
	r.mu.Unlock()
	return r.Runtime.Reset(ctx, spec)
}

func (r *duringStop) resetsDone() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.resets...)
}

func (r *duringStop) Stop(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	during := r.during
	r.during = nil
	r.mu.Unlock()
	if during != nil {
		during()
	}
	return r.Runtime.Stop(ctx, id)
}

// Review claim 3: a reset taken back, or an image changed, after the first gate (after the pull)
// and while the silo stops, must wipe nothing: the gate is taken again right before the reset,
// after the stop, and refuses a request that changed.
func TestAResetTakenBackWhileTheSiloStopsWipesNothing(t *testing.T) {
	for _, change := range []string{"reset taken back", "image changed"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
			ts := httptest.NewServer(srv)
			t.Cleanup(func() { cancel(); ts.Close() })
			c := client.New(ts.URL)
			_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
			rt := &duringStop{Runtime: fake.New()}
			a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
			go a.Run(ctx)
			e := &env{c: c, ctx: ctx}
			s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
				Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ghcr.io/acme/db:v1"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
			if err := c.Create(ctx, s); err != nil {
				t.Fatal(err)
			}
			s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
			if err := c.UpdateStatus(ctx, s); err != nil {
				t.Fatal(err)
			}
			e.wait(t, "db", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
			edit := func(f func(*v1.Silo)) {
				for {
					var cur v1.Silo
					if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
						t.Error(err)
						return
					}
					f(&cur)
					err := c.Update(ctx, &cur)
					if err == nil {
						return
					}
					if !client.IsConflict(err) {
						t.Error(err)
						return
					}
				}
			}
			stopped := make(chan struct{})
			rt.mu.Lock()
			rt.during = func() {
				if change == "reset taken back" {
					edit(func(s *v1.Silo) { s.Spec.Reset = "" })
				} else {
					edit(func(s *v1.Silo) { s.Spec.Reset = ""; s.Spec.Container.Image = "ghcr.io/acme/db:v2" })
				}
				close(stopped)
			}
			rt.mu.Unlock()
			edit(func(s *v1.Silo) { s.Spec.Reset = "2026-11-15T10:00:00Z" })
			select {
			case <-stopped:
			case <-time.After(10 * time.Second):
				t.Fatal("the reset never stopped the silo")
			}
			time.Sleep(time.Second) // the agent's next steps
			for _, image := range rt.resetsDone() {
				if image == "ghcr.io/acme/db:v1" {
					t.Fatalf("reset onto %s after the request changed while the silo stopped (%s): the disk is wiped (%v)", image, change, rt.CallLog())
				}
			}
			if change == "reset taken back" {
				e.wait(t, "db", func(s *v1.Silo) bool { return s.Status.Phase == agent.PhaseRunning })
			}
		})
	}
}
