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
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// §0.7: only a silo that asked for it (onControlPlaneLoss: Stop) is stopped when the host loses the
// control plane, and a healthy host never stops one: two heartbeats in a row may fail, plus a
// fence tick, and that stays under the shortest after admission takes. And the order that keeps
// two copies from running: for every after, the fence has killed the silo (worst case) before the
// control plane, counting from the same heartbeat on its own clock, may start it elsewhere
// (after + silo.StopMargin), with the clocks' rates off by twice what NTP allows.
func TestFenceTiming(t *testing.T) {
	if hb := worker.DefaultHeartbeat; 2*hb+fence.CheckEvery >= v1.MinStopAfter {
		t.Fatalf("heartbeat %s: two missed beats reach the shortest after, %s", hb, v1.MinStopAfter)
	}
	for _, after := range []time.Duration{v1.MinStopAfter, v1.DefaultStopAfter, time.Hour, v1.MaxStopAfter} {
		stopped := fence.WorstStopped(after) + after/1000 // the agent's clock running slow by 1000 ppm
		elsewhere := after + siloctl.StopMargin(after)
		if stopped >= elsewhere {
			t.Errorf("after %s: killed by %s at worst, started elsewhere from %s", after, stopped, elsewhere)
		}
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
	w := &fence.Watcher{Dir: dir, Runtimes: map[string]kri.Runtime{"docker": rt}, FenceAfter: fence.DefaultAfter}
	w.Check(ctx)
	calls := rt.CallLog()
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
	// web asked to stop; db is onHostLoss: Recreate, which says nothing about control-plane loss.
	for name, av := range map[string]v1.Availability{"web": {OnControlPlaneLoss: v1.OnControlPlaneLossStop}, "db": {OnHostLoss: v1.OnHostLossRecreate}} {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Availability: av}}
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
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: func() time.Time { return contact }, FenceDir: dir}
	stop := agent.RunForTest(t, ctx, a)
	var r fence.Record
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if r, _ = fence.Read(dir); len(r.Silos) == 2 {
			break
		}
	}
	stop()
	stops := map[string]bool{}
	for _, s := range r.Silos {
		stops[s.ID.Name] = s.StopAfter > 0
	}
	if !r.LastContact.Equal(contact) || r.Fence || len(r.Silos) != 2 || !stops["web"] || stops["db"] {
		t.Fatalf("record: %+v", r)
	}

	// Again, cut off: no contact in this run, and an API that doesn't answer.
	ts.Close()
	b := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": fake.New()}, Clock: clock.Real{},
		LastContact: func() time.Time { return time.Time{} }, FenceDir: dir}
	stop = agent.RunForTest(t, ctx, b)
	time.Sleep(2500 * time.Millisecond)
	stop()
	again, _ := fence.Read(dir)
	if !again.LastContact.Equal(contact) || len(again.Silos) != 2 || !again.Written.After(r.Written) {
		t.Fatalf("after a restart while cut off: %+v (before: %+v)", again, r)
	}
	if got := fence.Decide(again, contact.Add(v1.DefaultStopAfter+time.Second), fence.DefaultAfter, nil); len(got) != 1 || got[0].ID.Name != "web" {
		t.Fatalf("the watcher would stop %+v", got)
	}
}

// §0.7: the fence is inert unless a silo on the host asked to stop without the control plane;
// then it acts for that silo alone, on a one-node cluster too (where it stops every time the
// control plane is gone, which is why the docs say not to ask for it there).
func TestTheFenceIsInertWithoutAStopSilo(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel() // before the server closes: the agent's watches end first
	c := client.New(ts.URL)
	dir := t.TempDir()
	contact := time.Now().Add(-time.Hour)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	place := func(name string, av v1.Availability) kri.ID {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Availability: av}}
		if err := c.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host, s.Status.Phase = "cp1", "Scheduled"
		if err := c.UpdateStatus(ctx, s); err != nil {
			t.Fatal(err)
		}
		return kri.ID{Namespace: "dev", Name: name, UID: s.UID}
	}
	web := place("web", v1.Availability{OnHostLoss: v1.OnHostLossRecreate})
	rt := fake.New()
	a := &agent.Agent{Client: c, HostName: "cp1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		LastContact: func() time.Time { return contact }, FenceDir: dir,
		StopsOnLoss: func(s *v1.Silo) (bool, time.Duration) {
			stop, after := s.StopsOnControlPlaneLoss()
			return stop, after / 30
		}} // 30s → 1s
	agent.RunForTest(t, ctx, a)
	state := func(id kri.ID) kri.State { st, _ := rt.Status(ctx, id); return st.State }
	var r fence.Record
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if r, _ = fence.Read(dir); state(web) == kri.Running && len(r.Silos) == 1 {
			break
		}
	}
	time.Sleep(1500 * time.Millisecond) // a fence tick or two, an hour without contact
	if r, _ = fence.Read(dir); r.Written.IsZero() || len(fence.Decide(r, time.Now().Add(48*time.Hour), fence.DefaultAfter, nil)) > 0 {
		t.Fatalf("with no silo that asked to stop, the record stops something: %+v", r)
	}
	if got := state(web); got != kri.Running {
		t.Fatalf("an hour without the control plane stopped an onHostLoss: Recreate silo: %s", got)
	}

	stops := place("stops", v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: "30s"})
	// Placed here an hour into the outage: past its after already, so it isn't even started.
	for end := time.Now().Add(2500 * time.Millisecond); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if got := state(stops); got == kri.Running {
			t.Fatalf("the silo that asked to stop without the control plane was started without it")
		}
	}
	if r, _ = fence.Read(dir); len(r.Silos) != 2 || len(fence.Decide(r, time.Now(), fence.DefaultAfter, nil)) != 1 {
		t.Errorf("a silo here stops without the control plane, and the record doesn't stop it: %+v", r)
	}
	if got := state(web); got != kri.Running {
		t.Fatalf("the fence stopped the other silo too: %s", got)
	}
}
