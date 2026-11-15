package agent_test

import (
	"context"
	"net/http/httptest"
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

// unreadable is the strict fake as a runtime whose silo's state file became unreadable: its List
// no longer names the silo (the container and cloud-hypervisor runtimes skip a state file they
// can't read), while Status, Kill and Stop, which find a silo by its name, still do (K-094).
type unreadable struct {
	*fake.Strict
	hidden atomic.Bool
}

func (r *unreadable) List(ctx context.Context) ([]kri.ID, error) {
	if r.hidden.Load() {
		return nil, nil
	}
	return r.Strict.List(ctx)
}

// k105 is an agent on hv1, on a fake clock, with one container silo running on a runtime whose
// state file for it can be made unreadable.
type k105 struct {
	t   *testing.T
	ctx context.Context
	c   *client.Client
	clk *clock.Fake
	rt  *unreadable
	w   *fake.World
	id  kri.ID
}

func newK105(t *testing.T) *k105 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	clk := clock.NewFake(time.Unix(1_000_000, 0))
	w := fake.NewWorld()
	rt := &unreadable{Strict: fake.NewStrict("hv1", w)}
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clk, Log: t.Logf}
	agent.RunForTest(t, ctx, a)
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	k := &k105{t: t, ctx: ctx, c: c, clk: clk, rt: rt, w: w, id: kri.ID{Namespace: "dev", Name: "db", UID: s.UID}}
	k.until("the silo is reported Running", 100*time.Millisecond, func() bool { return k.get().Status.Phase == agent.PhaseRunning })
	return k
}

func (k *k105) get() *v1.Silo {
	var cur v1.Silo
	if err := k.c.Get(k.ctx, "Silo", "dev", "db", &cur); err != nil {
		k.t.Fatal(err)
	}
	return &cur
}

// until steps the agent's clock by step until cond holds (20s of real time at most); every look
// also checks that the silo's code never ran on two hosts.
func (k *k105) until(what string, step time.Duration, cond func() bool) {
	k.t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			k.t.Fatalf("never: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
		k.clk.Step(step)
	}
}

// still holds cond for the given real time, stepping the agent's clock by step.
func (k *k105) still(what string, d, step time.Duration, cond func() bool) {
	k.t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if !cond() {
			k.t.Fatalf("no longer: %s", what)
		}
		k.clk.Step(step)
	}
}

// K-105: a running silo whose state file is unreadable is invisible to its runtime's List. A
// handoff of it (a person's move: hv2 waits for hv1 to let go) must not be released while its
// code still runs here: it is stopped first (found by name), and its copy is kept, since what it
// holds can't be read.
func TestAHandoffOfASiloWhoseStateIsUnreadableIsReleasedOnlyOnceItNoLongerRuns(t *testing.T) {
	k := newK105(t)
	k.rt.hidden.Store(true)
	for {
		cur := k.get()
		cur.Status.Host, cur.Status.MovingFrom = "hv2", "hv1"
		err := k.c.UpdateStatus(k.ctx, cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	released := func() bool { cur := k.get(); return cur.Status.Host == "hv2" && cur.Status.MovingFrom == "" }
	k.until("the handoff is released", time.Millisecond, func() bool {
		if released() && k.w.RunsOn(k.id.UID, "hv1") {
			t.Fatalf("the handoff was released while the silo's code still runs on hv1 (calls %v)", k.rt.CallLog())
		}
		return released()
	})
	if k.w.RunsOn(k.id.UID, "hv1") {
		t.Fatalf("the silo still runs on hv1 after its handoff was released (calls %v)", k.rt.CallLog())
	}
	if ids, _ := k.rt.Strict.List(k.ctx); len(ids) != 1 {
		t.Fatalf("a copy whose state can't be read was removed: %v (calls %v)", ids, k.rt.CallLog())
	}
}

// The same silo deleted: its delete stops it here (nothing of a deleted silo runs on), and its
// copy, which the runtime can't read, is kept, not handed to a Delete that would remove nothing.
func TestADeleteOfASiloWhoseStateIsUnreadableStopsIt(t *testing.T) {
	k := newK105(t)
	k.rt.hidden.Store(true)
	if err := k.c.Delete(k.ctx, "Silo", "dev", "db"); err != nil {
		t.Fatal(err)
	}
	k.until("the deleted silo no longer runs on hv1", time.Millisecond, func() bool { return !k.w.RunsOn(k.id.UID, "hv1") })
	if ids, _ := k.rt.Strict.List(k.ctx); len(ids) != 1 {
		t.Fatalf("a copy whose state can't be read was handed to Delete: %v (calls %v)", ids, k.rt.CallLog())
	}
}

// And a silo still placed here whose state became unreadable is left running: it is this host's
// to run, and nothing stops it.
func TestASiloPlacedHereWhoseStateIsUnreadableKeepsRunning(t *testing.T) {
	k := newK105(t)
	k.rt.hidden.Store(true)
	k.still("the silo placed here runs", 300*time.Millisecond, 100*time.Millisecond, func() bool { return k.w.RunsOn(k.id.UID, "hv1") })
}
