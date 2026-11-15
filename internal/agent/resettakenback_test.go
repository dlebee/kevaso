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

// gatedVM is the fake shaped like cloud-hypervisor's reset path: a Pull, a Stop that returns once
// the VM is stopped (cloud-hypervisor presses its power button and waits up to 30s), then
// ResetGated, which stops it again, asks the agent's gate once nothing of it runs, and only then
// makes its disk afresh. at names the one point where change runs (a person taking the request
// back), synchronously, exactly once.
type gatedVM struct {
	*fake.Runtime
	mu      sync.Mutex
	at      string
	change  func()
	wiped   []string // the image of each disk made afresh (past the gate)
	refused int      // gates that refused
}

func (r *gatedVM) point(at string) {
	r.mu.Lock()
	change := r.change
	if r.at != at {
		change = nil
	} else {
		r.change = nil
	}
	r.mu.Unlock()
	if change != nil {
		change()
	}
}

func (r *gatedVM) Pull(_ context.Context, _ kri.ID, image string, _ *kri.RegistryAuth) (string, error) {
	r.point("during the pull")
	return "sha256:" + image, nil
}

func (r *gatedVM) Stop(ctx context.Context, id kri.ID) error {
	r.point("as the stop begins")
	err := r.Runtime.Stop(ctx, id)
	r.point("while the guest powers off") // stopped, and Stop hasn't returned yet
	return err
}

func (r *gatedVM) ResetGated(ctx context.Context, spec kri.Spec, gate func(context.Context) error) error {
	if err := r.Runtime.Stop(ctx, spec.ID); err != nil {
		return err
	}
	r.point("after the stop, right before the gate")
	if err := gate(ctx); err != nil {
		r.mu.Lock()
		r.refused++
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.wiped = append(r.wiped, spec.Image)
	r.mu.Unlock()
	return r.Runtime.Reset(ctx, spec)
}

func (r *gatedVM) result() ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.wiped...), r.refused
}

// Brief item 2 (TestMetal2VMResetTakenBackDuringStop on the machines): a microVM's reset taken
// back, or its image changed, at any point before the disk is made afresh, wipes nothing. The
// first gate (after the pull) and the second (inside ResetGated, once the VM is gone, right
// before lvremove) are each a compare-and-swap on the stored silo, against the generation the
// reset was decided on: clearing spec.reset or changing the image is a spec change, which bumps
// the generation, and either also makes the reset no longer due. Past the second gate the request
// is final; the machines' first run took it back there (once the unit was inactive) and the disk
// was rightly made again.
func TestAVMResetTakenBackAtAnyPointBeforeItsGateWipesNothing(t *testing.T) {
	for _, at := range []string{"during the pull", "as the stop begins", "while the guest powers off", "after the stop, right before the gate"} {
		for _, change := range []string{"reset taken back", "image changed"} {
			t.Run(at+"/"+change, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
				ts := httptest.NewServer(srv)
				t.Cleanup(func() { cancel(); ts.Close() })
				c := client.New(ts.URL)
				_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
				rt := &gatedVM{Runtime: fake.New()}
				a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
				agent.RunForTest(t, ctx, a)
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
				changed := make(chan struct{})
				rt.mu.Lock()
				rt.at, rt.change = at, func() {
					if change == "reset taken back" {
						e.edit(t, "db", func(s *v1.Silo) { s.Spec.Reset = "" })
					} else {
						e.edit(t, "db", func(s *v1.Silo) { s.Spec.Reset = ""; s.Spec.Container.Image = "ghcr.io/acme/db:v2" })
					}
					close(changed)
				}
				rt.mu.Unlock()
				e.edit(t, "db", func(s *v1.Silo) { s.Spec.Reset = "2026-11-15T10:00:00Z" })
				select {
				case <-changed:
				case <-time.After(10 * time.Second):
					t.Fatalf("the reset never got %s", at)
				}
				if change == "reset taken back" {
					e.wait(t, "db", func(s *v1.Silo) bool {
						return s.Status.Phase == agent.PhaseRunning && meta.IsTrue(s.Status.Conditions, "Ready")
					})
				} else {
					time.Sleep(time.Second) // the image changes without a resolved v2: nothing more happens
				}
				wiped, refused := rt.result()
				for _, image := range wiped {
					if image == "ghcr.io/acme/db:v1" {
						t.Fatalf("its disk was made afresh on v1 after the request changed %s (%s): %v", at, change, rt.CallLog())
					}
				}
				if at == "after the stop, right before the gate" && refused == 0 {
					t.Fatalf("the gate inside the reset never refused the changed request: %v", rt.CallLog())
				}
			})
		}
	}
}
