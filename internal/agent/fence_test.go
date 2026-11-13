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
func TestFenceTiming(t *testing.T) {
	fence, lease, recreate := agent.DefaultFenceAfter, hostctl.DefaultLease, siloctl.RecreateAfter
	if !(fence < lease && lease < lease+recreate) {
		t.Fatalf("FenceAfter %s < host lease %s < lease + RecreateAfter %s doesn't hold", fence, lease, lease+recreate)
	}
	if hb := worker.DefaultHeartbeat; hb >= fence {
		t.Fatalf("heartbeat %s isn't under FenceAfter %s: a healthy host would fence", hb, fence)
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
			Spec: v1.SiloSpec{Runtime: "docker", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
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
	if !r.LastContact.Equal(contact) || policies["web"] != v1.OnHostLossRecreate || policies["db"] != v1.OnHostLossWait {
		t.Fatalf("record: %+v", r)
	}

	// Again, cut off: no contact in this run, and an API that doesn't answer.
	ts.Close()
	runCtx, stop = context.WithCancel(ctx)
	b := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: func() time.Time { return time.Time{} }, FenceDir: dir}
	done = make(chan struct{})
	go func() { b.Run(runCtx); close(done) }()
	time.Sleep(2500 * time.Millisecond)
	stop()
	<-done
	again, _ := fence.Read(dir)
	if !again.LastContact.Equal(contact) || len(again.Silos) != 2 || !again.Written.After(r.Written) {
		t.Fatalf("after a restart while cut off: %+v (before: %+v)", again, r)
	}
	if got := fence.Decide(again, contact.Add(31*time.Second), agent.DefaultFenceAfter, nil); len(got) != 1 || got[0].ID.Name != "web" {
		t.Fatalf("the watcher would stop %+v", got)
	}
}
