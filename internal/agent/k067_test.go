package agent

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-067: the agent arms a silo's fence only while a watcher of this record version is seen
// running (its stamp, fresh), and disarms it when the watcher stops. The record of version 2
// carries nothing an older watcher acts on (no fence flag, no onHostLoss).
func TestArmedOnlyWhileAWatcherRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "validator", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, OnHostLoss: v1.OnHostLossRecreate}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a := &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{}, LastContact: time.Now, FenceDir: dir}
	RunForTest(t, ctx, a)
	get := func() *v1.Silo {
		var cur v1.Silo
		_ = c.Get(ctx, "Silo", "dev", "validator", &cur)
		return &cur
	}
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if fence.Armed(get()) {
			t.Fatal("armed with no watcher running")
		}
	}
	if r, _ := fence.Read(dir); r.Fence || len(r.Silos) != 1 || r.Silos[0].OnHostLoss != "" || r.Silos[0].StopAfter == 0 {
		t.Fatalf("the record an older watcher would read: %+v", r)
	}
	stamping, stop := atomic.Bool{}, make(chan struct{})
	stamping.Store(true)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
			}
			if stamping.Load() {
				_ = fence.WriteStamp(dir, fence.Stamp{Version: fence.RecordVersion, BootID: boottime.ID(), Boot: boottime.Now(), At: time.Now()})
			}
		}
	}()
	defer close(stop)
	for deadline := time.Now().Add(10 * time.Second); !fence.Armed(get()); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never armed with a watcher running: %+v", get().Status.Conditions)
		}
	}
	stamping.Store(false) // the watcher stopped
	for deadline := time.Now().Add(fence.StampFresh + 10*time.Second); fence.Armed(get()); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("still armed after the watcher stopped")
		}
	}
}

// failingKill fails its first kills.
type failingKill struct {
	*fake.Runtime
	fail atomic.Int32
}

func (f *failingKill) Kill(ctx context.Context, id kri.ID) error {
	if f.fail.Add(-1) >= 0 {
		return errors.New("busy")
	}
	return f.Stop(ctx, id)
}

// K-067: the agent's own fence counts a kill done only once it succeeded: a failed one is tried
// again on the next tick.
func TestAFailedKillIsTriedAgain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: "30s"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	rt := &failingKill{Runtime: fake.New()}
	rt.fail.Store(2)
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	a := &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		LastContact: func() time.Time { return time.Unix(0, last.Load()) },
		StopsOnLoss: func(s *v1.Silo) (bool, time.Duration) {
			stop, after := s.StopsOnControlPlaneLoss()
			return stop, after / 30
		}} // 30s → 1s
	RunForTest(t, ctx, a)
	id := kri.ID{Namespace: "dev", Name: "single", UID: s.UID}
	state := func() kri.State { st, _ := rt.Status(ctx, id); return st.State }
	for deadline := time.Now().Add(10 * time.Second); state() != kri.Running; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("never ran")
		}
	}
	// Contact ends now; the first two kills fail.
	for deadline := time.Now().Add(10 * time.Second); state() == kri.Running; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("still running: a failed kill counted as done, and never tried again")
		}
	}
}
