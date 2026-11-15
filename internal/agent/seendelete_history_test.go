package agent_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// review-batch4 claim 1: only a delete event of the delete watch, on a history this worker
// accepts and while it isn't held, is a delete seen here. A NotFound, or another silo of that
// name, at the start claim or its renewal is not: a control plane restored from an older backup
// (kvoadm init --restore: a new history the worker accepts) or a system node behind says the same
// of a silo nobody deleted. Before the fix each of these removed the silo's disk.

// controlPlanes is the control plane the worker reaches: one of several stores (a restore, a
// lagging system node), each answer stamped as the test says. A switch closes the worker's
// connections, so every later answer is of the new one.
type controlPlanes struct {
	mu      sync.Mutex
	to      http.Handler
	seen    client.ControlPlaneSeen
	noWatch bool // watches refused (the delete watch, and the cache's, are down)
	ts      *httptest.Server
}

func (c *controlPlanes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	to, seen, noWatch := c.to, c.seen, c.noWatch
	c.mu.Unlock()
	client.SetControlPlane(w.Header(), seen)
	if noWatch && r.URL.Query().Get("watch") == "true" {
		http.Error(w, "no watch here", http.StatusServiceUnavailable)
		return
	}
	to.ServeHTTP(w, r)
}

func (c *controlPlanes) switchTo(to http.Handler, seen client.ControlPlaneSeen) {
	c.mu.Lock()
	c.to, c.seen = to, seen
	c.mu.Unlock()
	c.ts.CloseClientConnections()
}

// historyRig: control plane A (cluster c1, history h1), a worker hv1 trusting it, with a strict
// container fake, a fake clock and a watermark file (seen-deletes.json next to it).
type historyRig struct {
	t      *testing.T
	ctx    context.Context
	cp     *controlPlanes
	a      *agent.Agent
	clk    *clock.Fake
	rt     *fake.Strict
	w      *fake.World
	file   string // the watermark
	srvA   http.Handler
	cA     *client.Client
	id     kri.ID
	stores map[http.Handler]*client.Client
}

var (
	seenA      = client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 100}
	seenLag    = client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 50} // a system node behind
	seenRestor = client.ControlPlaneSeen{ClusterID: "c1", History: "h2", Epoch: 2, Revision: 10} // kvoadm init --restore
)

// newStore is an API server with namespace dev and Host hv1 (as a restored backup has them), and
// a direct, unjudged client to it for the test.
func (r *historyRig) newStore() (http.Handler, *client.Client) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	r.t.Cleanup(ts.Close)
	c := client.New(ts.URL)
	_ = c.Create(r.ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	if err := c.Create(r.ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		r.t.Fatal(err)
	}
	r.stores[srv] = c
	return srv, c
}

func newHistoryRig(t *testing.T) *historyRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	r := &historyRig{t: t, ctx: ctx, clk: clock.NewFake(time.Unix(1_000_000, 0)), w: fake.NewWorld(), stores: map[http.Handler]*client.Client{}}
	r.srvA, r.cA = r.newStore()
	r.cp = &controlPlanes{to: r.srvA, seen: seenA}
	r.cp.ts = httptest.NewServer(r.cp)
	t.Cleanup(r.cp.ts.Close)
	r.rt = fake.NewStrict("hv1", r.w)
	r.file = filepath.Join(t.TempDir(), "control-plane-watermark.json")
	return r
}

// start runs a new agent on hv1 (a kevasod start), renewing claims every minute of the fake clock.
func (r *historyRig) start(rt kri.Runtime) (stop func()) {
	cl := client.New(r.cp.ts.URL)
	r.a = &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: r.clk,
		Log: r.t.Logf, WatermarkFile: r.file, ClaimRefresh: time.Minute}
	cl.ControlPlane = r.a.ControlPlaneJudge()
	return agent.RunForTest(r.t, r.ctx, r.a)
}

// place makes dev/single in the store c talks to, placed on host (none: ""), init steps as given.
func (r *historyRig) place(c *client.Client, host string, steps ...v1.InitStep) kri.ID {
	r.t.Helper()
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if len(steps) > 0 {
		s.Spec.Init = &v1.Init{Steps: steps}
	}
	if err := c.Create(r.ctx, s); err != nil {
		r.t.Fatal(err)
	}
	if host != "" {
		s.Status.Host, s.Status.Phase = host, "Scheduled"
		if err := c.UpdateStatus(r.ctx, s); err != nil {
			r.t.Fatal(err)
		}
	}
	return kri.ID{Namespace: "dev", Name: "single", UID: s.UID}
}

// waitFor waits (real time) for ok, stepping the fake clock by a millisecond now and then.
func (r *historyRig) waitFor(what string, ok func() bool) {
	r.t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			r.t.Fatalf("never: %s", what)
		}
		r.clk.Step(time.Millisecond)
	}
}

// renew steps the fake clock past a claim refresh: the keeper's renewal reads the store now.
func (r *historyRig) renew() {
	r.clk.Step(time.Minute + time.Second)
	time.Sleep(100 * time.Millisecond)
}

// trusted waits until the worker's watermark on disk is seen's history.
func (r *historyRig) trusted(seen client.ControlPlaneSeen) {
	r.t.Helper()
	r.waitFor("the worker trusts history "+seen.History, func() bool {
		b, _ := os.ReadFile(r.file)
		return strings.Contains(string(b), `"history":"`+seen.History+`"`) && !strings.Contains(string(b), `"held":true`)
	})
}

// holdsFor says, over d of real time (stepping the fake clock a second at a time: requeues,
// backoffs and the Host's report all happen), that the copy id is still here and its UID never
// in seen-deletes.json.
func (r *historyRig) keptFor(id kri.ID, d time.Duration) {
	r.t.Helper()
	deletes := filepath.Join(filepath.Dir(r.file), agent.SeenDeletesFile)
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if !holds(r.t, r.rt, id.UID) {
			r.t.Fatalf("the copy of %s was removed, though nobody deleted it", id)
		}
		if b, _ := os.ReadFile(deletes); strings.Contains(string(b), id.UID) {
			r.t.Fatalf("%s recorded as a seen delete, though nobody deleted it: %s", id, b)
		}
		r.clk.Step(time.Second)
	}
}

// listed waits for the Host in the store c talks to to list id as kept.
func (r *historyRig) listed(c *client.Client, id kri.ID) {
	r.t.Helper()
	r.waitFor("dev/single listed in KeptSilos", func() bool {
		r.clk.Step(time.Second)
		var h v1.Host
		_ = c.Get(r.ctx, "Host", "", "hv1", &h)
		k := meta.FindCondition(h.Status.Conditions, agent.ConditionKeptSilos)
		return k != nil && k.Status == meta.ConditionTrue && strings.Contains(k.Message, "dev/single uid "+id.UID[:8])
	})
}

func slowInit(rt *fake.Strict) v1.InitStep {
	rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return make(chan struct{}) } // until killed
	return v1.InitStep{Name: "slow", Run: "sleep 300"}
}

// A restore during a start: the restored store doesn't have the silo, or has another of that
// name. The start ends (nothing of it runs), and the copy is kept, listed, never removed.
func TestARestoreDuringAStartKeepsTheCopy(t *testing.T) {
	for _, other := range []bool{false, true} {
		name := "the restored store lacks it"
		if other {
			name = "the restored store has another silo of that name"
		}
		t.Run(name, func(t *testing.T) {
			r := newHistoryRig(t)
			r.start(r.rt)
			r.trusted(seenA)
			r.id = r.place(r.cA, "hv1", slowInit(r.rt))
			r.waitFor("the init step runs", func() bool { return r.rt.RunningInit(r.id) == "slow" })
			srvB, cB := r.newStore()
			if other {
				r.place(cB, "") // another silo dev/single, a new UID, placed nowhere
			}
			r.cp.switchTo(srvB, seenRestor)
			r.trusted(seenRestor)
			r.renew()
			r.waitFor("the start ended: nothing of it runs on hv1", func() bool { return !r.w.RunsOn(r.id.UID, "hv1") })
			r.keptFor(r.id, 2*time.Second)
			r.listed(cB, r.id)
		})
	}
}

// A restore while it runs (its start long finished): kept running, listed.
func TestARestoreWhileASiloRunsKeepsItRunning(t *testing.T) {
	r := newHistoryRig(t)
	r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	srvB, cB := r.newStore()
	r.cp.switchTo(srvB, seenRestor)
	r.trusted(seenRestor)
	r.renew()
	r.keptFor(r.id, 2*time.Second)
	if st, _ := r.rt.Status(r.ctx, r.id); st.State != kri.Running {
		t.Fatalf("a silo the restored state doesn't know was stopped: %s", st.State)
	}
	r.listed(cB, r.id)
}

// A system node behind answers the renewal NotFound (judged Hold). Nothing is recorded; later the
// caught-up node answers, then a restore whose store lacks the silo: the copy is still kept.
// Before the fix the held NotFound stayed in seen-deletes.json and the restore removed the disk.
func TestALaggingNodesNotFoundIsNoDelete(t *testing.T) {
	r := newHistoryRig(t)
	r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1", slowInit(r.rt))
	r.waitFor("the init step runs", func() bool { return r.rt.RunningInit(r.id) == "slow" })
	lag, _ := r.newStore() // behind: it doesn't have the silo yet
	r.cp.switchTo(lag, seenLag)
	r.waitFor("held", func() bool {
		b, _ := os.ReadFile(r.file)
		return strings.Contains(string(b), `"held":true`)
	})
	r.renew()
	r.keptFor(r.id, time.Second)
	r.cp.switchTo(r.srvA, seenA) // the caught-up node
	r.trusted(seenA)
	r.keptFor(r.id, time.Second)
	srvB, cB := r.newStore()
	r.cp.switchTo(srvB, seenRestor)
	r.trusted(seenRestor)
	r.renew()
	r.keptFor(r.id, 2*time.Second)
	r.listed(cB, r.id)
}

// A silo deleted and made again under the same name, during its start. With the delete watch down
// the renewal finds another UID: not a delete seen, the old copy is kept. With the watch up its
// delete is seen and its copy removed at once (the machines' case, metal.md, which must stay).
func TestASiloRemadeUnderItsNameIsRemovedOnlyOnItsOwnDelete(t *testing.T) {
	for _, watched := range []bool{false, true} {
		name := "its delete not seen"
		if watched {
			name = "its delete seen on the watch"
		}
		t.Run(name, func(t *testing.T) {
			r := newHistoryRig(t)
			r.cp.noWatch = !watched
			r.start(r.rt)
			r.trusted(seenA)
			r.id = r.place(r.cA, "hv1", slowInit(r.rt))
			r.waitFor("the init step runs", func() bool { return r.rt.RunningInit(r.id) == "slow" })
			if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
				t.Fatal(err)
			}
			r.place(r.cA, "") // made again, a new UID, placed nowhere yet
			if watched {
				r.waitFor("the init step ended on hv1", func() bool { return !r.w.RunsOn(r.id.UID, "hv1") })
				r.waitFor("the old copy removed", func() bool { return !holds(t, r.rt, r.id.UID) })
				return
			}
			r.renew()
			r.waitFor("the start ended: nothing of it runs on hv1", func() bool { return !r.w.RunsOn(r.id.UID, "hv1") })
			r.keptFor(r.id, 2*time.Second)
			r.listed(r.cA, r.id)
		})
	}
}

// failingDelete is the strict fake whose Delete fails while fail is set (a removal under way when
// kevasod stops).
type failingDelete struct {
	*fake.Strict
	mu   sync.Mutex
	fail bool
}

func (f *failingDelete) Delete(ctx context.Context, id kri.ID) error {
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errFailingDelete
	}
	return f.Strict.Delete(ctx, id)
}

var errFailingDelete = &client.Error{Code: 503, Reason: "EngineDown", Message: "the engine doesn't answer"}

// A delete seen on the watch under history h1, its removal not finished, then kevasod restarts on
// a restored control plane (h2) that doesn't have the silo: the entry of h1 is not honoured under
// h2, and the copy is kept, listed.
func TestADeleteSeenUnderAnotherHistoryIsNotHonoured(t *testing.T) {
	r := newHistoryRig(t)
	rt := &failingDelete{Strict: r.rt}
	stop := r.start(rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	rt.mu.Lock()
	rt.fail = true
	rt.mu.Unlock()
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	deletes := filepath.Join(filepath.Dir(r.file), agent.SeenDeletesFile)
	r.waitFor("the delete kept on disk", func() bool {
		b, _ := os.ReadFile(deletes)
		return strings.Contains(string(b), r.id.UID)
	})
	stop()
	rt.mu.Lock()
	rt.fail = false
	rt.mu.Unlock()
	srvB, cB := r.newStore()
	r.cp.switchTo(srvB, seenRestor)
	r.start(rt)
	r.trusted(seenRestor)
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if !holds(t, r.rt, r.id.UID) {
			t.Fatal("a delete seen under history h1 removed the copy under h2")
		}
		r.clk.Step(time.Second)
	}
	r.listed(cB, r.id)
}
