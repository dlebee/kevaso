package agent_test

import (
	"context"
	"io"
	"net/http"
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

// frozenWatches serves the API, except that while frozen a watch gets no events: the agent's
// cache stays as it was (a host whose watch hasn't caught up after contact came back).
type frozenWatches struct {
	h      http.Handler
	frozen atomic.Bool
	silos  atomic.Int32 // Silo watches held while frozen
}

func (f *frozenWatches) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.frozen.Load() && r.URL.Query().Get("watch") != "" {
		if strings.HasSuffix(r.URL.Path, "/silos") {
			f.silos.Add(1)
		}
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-r.Context().Done()
		return
	}
	f.h.ServeHTTP(w, r)
}

// K-015: an opted-in silo was stopped by its host's fence and started elsewhere by the control
// plane; its old host, its silo cache from before (placed here), must not start it again, nor
// write its phase on a silo that is now another host's. Every start reads the stored silo first.
func TestASiloIsNeverStartedFromACacheThatSaysItIsStillHere(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	fw := &frozenWatches{h: srv}
	ts := httptest.NewServer(fw)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := fake.New()
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf,
		Resync: 300 * time.Millisecond}
	go a.Run(ctx)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, OnHostLoss: v1.OnHostLossRecreate}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	id := kri.ID{Namespace: "dev", Name: "single", UID: s.UID}
	state := func() kri.State { st, _ := rt.Status(ctx, id); return st.State }
	for deadline := time.Now().Add(10 * time.Second); state() != kri.Running; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never ran: %s", state())
		}
	}
	// The fence killed it here; the control plane placed it on hv2. hv1's watch hasn't caught up.
	fw.frozen.Store(true)
	ts.CloseClientConnections() // the agent watches again, and gets nothing
	// An informer lists before it watches: both Silo watchers (the cache, the delete watch) held
	// means both listed again while the silo was still placed here. Deterministic, no sleep.
	for deadline := time.Now().Add(10 * time.Second); fw.silos.Load() < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the agent's Silo watches never came back (%d)", fw.silos.Load())
		}
	}
	if err := kri.Kill(ctx, rt, id); err != nil {
		t.Fatal(err)
	}
	for {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", "dev", "single", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.Host, cur.Status.Phase, cur.Status.Conditions = "hv2", "Running", nil
		err := c.UpdateStatus(ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if got := state(); got == kri.Running {
			t.Fatal("started again on hv1 from a cache that says it's still here: two copies")
		}
	}
	var cur v1.Silo
	if err := c.Get(ctx, "Silo", "dev", "single", &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Status.Host != "hv2" || cur.Status.Phase != "Running" {
		t.Fatalf("hv1 wrote over hv2's silo: host %s phase %s", cur.Status.Host, cur.Status.Phase)
	}
}

// initRacer runs an init step that moves the stored silo to another host while it runs: the
// control plane committing a restart elsewhere in the gap between the agent's read and its start.
type initRacer struct {
	*fake.Runtime
	moved   atomic.Bool
	onInit  func()
	started atomic.Int32
}

func (r *initRacer) RunInit(context.Context, kri.ID, kri.InitStep, io.Writer) (int, error) {
	if r.moved.CompareAndSwap(false, true) {
		r.onInit()
	}
	return 0, nil
}

func (r *initRacer) Start(ctx context.Context, id kri.ID) error {
	r.started.Add(1)
	return r.Runtime.Start(ctx, id)
}

// K-015, the gap a read can't close: the silo is placed elsewhere after the agent's last read and
// before its start (here, while its init step runs). The start is conditional on a write: the
// agent must win a compare-and-swap of its start claim on the version it read, and a status write
// that finds the silo placed elsewhere stops the start.
func TestAPlacementChangeAfterTheReadStopsTheStart(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := &initRacer{Runtime: fake.New()}
	rt.onInit = func() {
		for {
			var cur v1.Silo
			if err := c.Get(ctx, "Silo", "dev", "single", &cur); err != nil {
				t.Error(err)
				return
			}
			cur.Status.Host, cur.Status.Phase = "hv2", "Scheduled"
			err := c.UpdateStatus(ctx, &cur)
			if err == nil {
				return
			}
			if !client.IsConflict(err) {
				t.Error(err)
				return
			}
		}
	}
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	go a.Run(ctx)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Init: &v1.Init{Steps: []v1.InitStep{{Name: "slow", Run: "sleep 20"}}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); !rt.moved.Load(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the init step never ran")
		}
	}
	time.Sleep(2 * time.Second) // the agent's next steps, and a retry or two
	if n := rt.started.Load(); n != 0 {
		t.Fatalf("started %d times on hv1 after the control plane placed it on hv2: two copies", n)
	}
	var cur v1.Silo
	_ = c.Get(ctx, "Silo", "dev", "single", &cur)
	if cur.Status.Host != "hv2" {
		t.Fatalf("hv1 wrote over hv2's placement: %s", cur.Status.Host)
	}
}
