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
	hostctl "kevaso.com/core/internal/controllers/host"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// The order that keeps two copies from running: the old host fences (its agent, or the fence
// watcher when the agent is gone) before the control plane calls it lost, and the control plane
// recreates only RecreateAfter later. The heartbeat period counts too: the record's last contact
// can already be that old when the agent stops.
//
// Both sides count from the same moment, the last heartbeat that got through: the worst case of
// "record goes stale → every silo killed" must stay under the earliest "host declared lost →
// started elsewhere" by fence.MinMargin. If it doesn't, change the timings, not this test.
func TestFenceTiming(t *testing.T) {
	after, lease, recreate := agent.DefaultFenceAfter, hostctl.DefaultLease, siloctl.RecreateAfter
	if after >= lease {
		t.Fatalf("FenceAfter %s isn't under the host lease %s: the host is called lost before it fences", after, lease)
	}
	stopped := fence.WorstStopped(after)
	elsewhere := lease + recreate - fence.MaxSkew
	if margin := elsewhere - stopped; margin < fence.MinMargin {
		t.Fatalf("every silo killed by %s, another copy as early as %s: margin %s < %s", stopped, elsewhere, margin, fence.MinMargin)
	}
	// A healthy host never fences: two heartbeats in a row may fail and it still doesn't.
	if hb := worker.DefaultHeartbeat; 2*hb+fence.CheckEvery >= after {
		t.Fatalf("heartbeat %s: two missed beats reach FenceAfter %s", hb, after)
	}
}

// A fence kills (kri.Kill): no runtime's graceful stop and its grace period in the way.
func TestWatcherKills(t *testing.T) {
	ctx := context.Background()
	rt := fake.New()
	id := kri.ID{Namespace: "dev", Name: "web", UID: "u1"}
	_ = rt.Create(ctx, kri.Spec{ID: id})
	_ = rt.Start(ctx, id)
	dir := t.TempDir()
	now := time.Now()
	_ = fence.Write(dir, fence.Record{LastContact: now.Add(-time.Minute), Fence: true,
		Silos: []fence.Silo{{ID: id, Runtime: "docker", OnHostLoss: v1.OnHostLossRecreate}}})
	w := &fence.Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: agent.DefaultFenceAfter}
	w.Check(ctx)
	calls := rt.Calls
	if len(calls) == 0 || calls[len(calls)-1] != "kill dev/web" {
		t.Fatalf("calls: %v", calls)
	}
}

// The agent writes the fence record every second: its last contact, and the onHostLoss of each
// silo on this host. Started again while cut off (no contact yet, the API unreachable), it keeps
// what its earlier run recorded, so the watcher still fences on time.
func TestAgentWritesTheFenceRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	for name, policy := range map[string]string{"web": v1.OnHostLossRecreate, "db": ""} {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Availability: v1.Availability{OnHostLoss: policy}}}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	contact := time.Now().Add(-5 * time.Second).UTC().Truncate(time.Second)
	runCtx, stop := context.WithCancel(ctx)
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: func() time.Time { return contact }, FenceDir: dir}
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	var r fence.Record
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if r, _ = fence.Read(dir); len(r.Silos) == 2 {
			break
		}
	}
	stop()
	<-done
	policies := map[string]string{}
	for _, s := range r.Silos {
		policies[s.ID.Name] = s.OnHostLoss
	}
	if !r.LastContact.Equal(contact) || !r.Fence || policies["web"] != v1.OnHostLossRecreate || policies["db"] != v1.OnHostLossWait {
		t.Fatalf("record: %+v", r)
	}

	// Again, cut off: no contact in this run, and an API that doesn't answer.
	ts.Close()
	runCtx, stop = context.WithCancel(ctx)
	b := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: func() time.Time { return time.Time{} }, FenceDir: dir,
		FenceApplies: func() (bool, bool) { return false, false }} // a control plane that can't tell yet
	done = make(chan struct{})
	go func() { b.Run(runCtx); close(done) }()
	time.Sleep(2500 * time.Millisecond)
	stop()
	<-done
	again, _ := fence.Read(dir)
	if !again.LastContact.Equal(contact) || !again.Fence || len(again.Silos) != 2 || !again.Written.After(r.Written) {
		t.Fatalf("after a restart while cut off: %+v (before: %+v)", again, r)
	}
	if got := fence.Decide(again, contact.Add(31*time.Second), agent.DefaultFenceAfter, nil); len(got) != 1 || got[0].ID.Name != "web" {
		t.Fatalf("the watcher would stop %+v", got)
	}
}

// On a host whose silos nobody could start elsewhere (a one-node cluster with a worker), the
// record says no fence applies: neither the watcher nor the agent's own fence stops anything,
// however long the contact is gone.
func TestNoFenceWhereNobodyRecreates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	dir := t.TempDir()
	contact := time.Now().Add(-time.Hour)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "cp1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	rt := fake.New()
	id := kri.ID{Namespace: "dev", Name: "web", UID: s.UID}
	runCtx, stop := context.WithCancel(ctx)
	a := &agent.Agent{Client: c, HostName: "cp1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		LastContact: func() time.Time { return contact }, FenceDir: dir, FenceApplies: func() (bool, bool) { return false, true }}
	done := make(chan struct{})
	go func() { a.Run(runCtx); close(done) }()
	var r fence.Record
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		r, _ = fence.Read(dir)
		if st, _ := rt.Status(ctx, id); st.State == kri.Running && len(r.Silos) == 1 {
			break
		}
	}
	time.Sleep(1500 * time.Millisecond) // a fence tick or two
	stop()
	<-done
	if r.Written.IsZero() || r.Fence {
		t.Fatalf("record: %+v", r)
	}
	if st, _ := rt.Status(ctx, id); st.State != kri.Running {
		t.Fatalf("the agent fenced a silo nobody could start elsewhere: %s", st.State)
	}
}
