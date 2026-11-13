package agent

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// recordingRuntime checks the fence record when a silo starts, and can refuse deletes.
type recordingRuntime struct {
	*fake.Runtime
	dir          string
	startedKnown atomic.Int32 // 1: recorded when started, 2: not
	holdDelete   atomic.Bool
}

func (r *recordingRuntime) Start(ctx context.Context, id kri.ID) error {
	rec, _ := fence.Read(r.dir)
	v := int32(2)
	for _, s := range rec.Silos {
		if s.ID.UID == id.UID && s.OnHostLoss == v1.OnHostLossRecreate {
			v = 1
		}
	}
	r.startedKnown.CompareAndSwap(0, v)
	return r.Runtime.Start(ctx, id)
}

func (r *recordingRuntime) Delete(ctx context.Context, id kri.ID) error {
	if r.holdDelete.Load() {
		return errors.New("busy")
	}
	return r.Runtime.Delete(ctx, id)
}

// The fence record covers a silo for as long as this host may run it: recorded before it starts,
// and kept (with its policy) after the API places it elsewhere, until the runtime no longer has it.
func TestFenceRecordCoversTheSiloWhileItCanRun(t *testing.T) {
	old := goneEvery
	goneEvery = 0
	defer func() { goneEvery = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rt := &recordingRuntime{Runtime: fake.New(), dir: dir}
	a := &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		LastContact: time.Now, FenceDir: dir}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	defer func() { stop(); <-done }()
	id := kri.ID{Namespace: "dev", Name: "web", UID: s.UID}
	recorded := func() bool {
		r, _ := fence.Read(dir)
		for _, x := range r.Silos {
			if x.ID.UID == s.UID {
				return true
			}
		}
		return false
	}
	waitFor := func(what string, f func() bool) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); !f(); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out: %s", what)
			}
		}
	}
	waitFor("started", func() bool { st, _ := rt.Status(ctx, id); return st.State == kri.Running })
	if rt.startedKnown.Load() != 1 {
		t.Fatal("the silo started before its policy was in the fence record")
	}

	// Placed elsewhere while its copy here can't be removed yet: still recorded.
	rt.holdDelete.Store(true)
	for { // the agent writes this silo's status too: read again on a conflict
		_ = c.Get(ctx, "Silo", "dev", "web", s)
		s.Status.Host = "hv2"
		err := c.UpdateStatus(ctx, s)
		if client.IsConflict(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	time.Sleep(2500 * time.Millisecond)
	if !recorded() {
		t.Fatal("dropped from the record while the runtime still has it")
	}
	// Gone from the runtime: only now out of the record.
	rt.holdDelete.Store(false)
	waitFor("removed from the runtime", func() bool { st, _ := rt.Status(ctx, id); return st.State == kri.Absent })
	waitFor("out of the record", func() bool { return !recorded() })
}

// Once in contact, the watcher's report goes on the Host (FenceFaults) and the report is removed.
func TestAgentReportsFenceFaults(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "192.0.2.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	at := time.Now().Add(-time.Minute)
	if err := fence.WriteFaults(dir, fence.Faults{At: at, Silos: []fence.Silo{{ID: kri.ID{Namespace: "dev", Name: "stray", UID: "u9"}, Runtime: "docker"}}}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: time.Now, FenceDir: dir}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	defer func() { stop(); <-done }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		var h v1.Host
		_ = c.Get(ctx, "Host", "", "hv1", &h)
		if cond := meta.FindCondition(h.Status.Conditions, fence.ConditionFaults); cond != nil {
			if cond.Status != meta.ConditionTrue || !strings.Contains(cond.Message, "dev/stray") {
				t.Fatalf("condition: %+v", cond)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no FenceFaults condition on the Host")
		}
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, ok, _ := fence.ReadFaults(dir); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the report wasn't removed")
		}
	}
}
