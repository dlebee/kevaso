package agent

import (
	"context"
	"net/http/httptest"
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

// Brainstorm §0.7, the agent's half of onControlPlaneLoss: Stop (host lane; the control plane's
// half is in internal/controllers/silo and internal/fence). The agent's fence record must be
// version 2: each silo with its StopAfter from (*v1.Silo).StopsOnControlPlaneLoss() (0 when it
// continues), whatever onHostLoss says; LastContact the time the last successful heartbeat write
// was SENT. Once that record is on disk, the agent writes fence.ArmedCondition(host, after,
// generation) on the silo's status; the control plane restarts the silo elsewhere only while
// fence.Armed holds. The agent's own fence (agent.go, a.fenced) follows the same rule: it stops
// only StopAfter silos, each after its own after.
func TestStopSilosAreRecordedWithTheirAfter(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{HostName: "hv1", Clock: clock.Real{}, LastContact: time.Now, FenceDir: dir}
	stop := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "validator", Namespace: "dev", UID: "u1", Generation: 2}}
	stop.Spec.Runtime = "docker"
	stop.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	stop.Spec.Availability.OnControlPlaneLoss, stop.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	keep := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", UID: "u2", Generation: 1}}
	keep.Spec.Runtime = "docker"
	keep.Spec.Availability.OnHostLoss = v1.OnHostLossMove // moves on a confirmation only: never stopped by a fence
	for _, s := range []*v1.Silo{stop, keep} {
		if err := a.recordForFence(s); err != nil {
			t.Fatal(err)
		}
	}
	r, err := fence.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != fence.RecordVersion {
		t.Fatalf("record version %d, want %d", r.Version, fence.RecordVersion)
	}
	for _, s := range r.Silos {
		want := map[string]time.Duration{"u1": 45 * time.Second, "u2": 0}[s.ID.UID]
		if s.StopAfter != want {
			t.Errorf("%s: StopAfter %v, want %v", s.ID.Name, s.StopAfter, want)
		}
	}
}

// The control plane restarts an opted-in silo elsewhere only while its host has armed the fence
// for it (fence.Armed): the agent arms it once the silo's entry is in the record on disk, for its
// host, after and generation, and disarms it when the silo no longer asks to stop.
func TestTheFenceIsArmedOnlyOnceTheRecordHoldsTheSilo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "validator", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: "45s"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	a := &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: time.Now, FenceDir: dir}
	RunForTest(t, ctx, a)
	stampLikeAWatcher(t, ctx, dir) // armed means a watcher runs (K-067)
	get := func() *v1.Silo {
		var cur v1.Silo
		if err := c.Get(ctx, "Silo", "dev", "validator", &cur); err != nil {
			t.Fatal(err)
		}
		return &cur
	}
	for deadline := time.Now().Add(10 * time.Second); !fence.Armed(get()); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never armed: %+v", get().Status.Conditions)
		}
	}
	r, _ := fence.Read(dir)
	if len(r.Silos) != 1 || r.Silos[0].StopAfter != 45*time.Second {
		t.Fatalf("armed, and the record on disk doesn't hold it: %+v", r)
	}
	// No longer asking to stop: disarmed.
	for {
		cur := get()
		cur.Spec.Availability = v1.Availability{}
		err := c.Update(ctx, cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		cur := get()
		if c := meta.FindCondition(cur.Status.Conditions, fence.ConditionArmed); c != nil && c.Status != meta.ConditionTrue {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still armed after the silo stopped asking: %+v", cur.Status.Conditions)
		}
	}
	// Disarmed first, the record follows (within a fence tick): the control plane stops counting on
	// the fence before the fence stops acting.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if r, _ := fence.Read(dir); len(r.Silos) == 1 && r.Silos[0].StopAfter == 0 {
			break
		}
		if time.Now().After(deadline) {
			r, _ := fence.Read(dir)
			t.Fatalf("the record still stops it: %+v", r)
		}
	}
}

// stampLikeAWatcher writes the fence watcher's stamp until ctx ends or the test does. It stops,
// and is waited for, in a cleanup registered after dir's: before dir is removed, or the removal
// races its last write ("directory not empty").
func stampLikeAWatcher(t testing.TB, ctx context.Context, dir string) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = fence.WriteStamp(dir, fence.Stamp{Version: fence.RecordVersion, BootID: boottime.ID(), Boot: boottime.Now(), At: time.Now()})
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
}
