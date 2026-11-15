package agent_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// cpHeaders serves the API with the control-plane headers the test sets (cluster, history, epoch,
// revision): what a control plane that lost its data, a restore, or another cluster would say.
type cpHeaders struct {
	mu   sync.Mutex
	seen client.ControlPlaneSeen
	h    http.Handler
}

func (c *cpHeaders) set(s client.ControlPlaneSeen) { c.mu.Lock(); c.seen = s; c.mu.Unlock() }

func (c *cpHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	s := c.seen
	c.mu.Unlock()
	client.SetControlPlane(w.Header(), s)
	c.h.ServeHTTP(w, r)
}

// §0.7, the worker's side of control.md's contract: a control plane older than what the worker
// saw (Hold) or of another cluster (Foreign) changes nothing on the host: every silo keeps
// running, nothing new starts, nothing is removed. The hold is kept on disk, survives a restart
// and stays after the revision catches up; the Host says ControlPlaneBehind. Only a new history
// (a deliberate restore) clears it, and what the restored state doesn't know is kept.
func TestAHeldWorkerChangesNothingUntilANewHistory(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	cp := &cpHeaders{h: srv, seen: client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 100}}
	ts := httptest.NewServer(cp)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	rt := fake.New()
	rt.Handler = func(kri.ID, []string, []byte) (string, int) { return "", 0 }
	start := func() context.CancelFunc {
		actx, stop := context.WithCancel(ctx)
		cl := client.New(ts.URL)
		a := &agent.Agent{Client: cl, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt},
			Clock: clock.Real{}, WatermarkFile: file, Log: t.Logf}
		cl.ControlPlane = a.ObserveControlPlane
		done := make(chan struct{})
		go func() { a.Run(actx); close(done) }()
		return func() { stop(); <-done }
	}
	stop := start()
	e := &env{c: c, rt: rt, ctx: ctx}
	e.place(t, "web", "hv1", nil)
	e.wait(t, "web", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	state := func(name string) kri.State {
		ids, _ := rt.List(ctx)
		for _, id := range ids {
			if id.Name == name {
				st, _ := rt.Status(ctx, id)
				return st.State
			}
		}
		return kri.Absent
	}
	kept := func() client.Watermark {
		var w client.Watermark
		b, err := os.ReadFile(file)
		if err == nil {
			err = json.Unmarshal(b, &w)
		}
		if err != nil {
			t.Fatalf("the watermark on disk: %v", err)
		}
		return w
	}
	if w := kept(); w.ClusterID != "c1" || w.History != "h1" || w.Revision != 100 || w.Held {
		t.Fatalf("after the first contact: %+v", w)
	}
	behind := func() *meta.Condition {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		return meta.FindCondition(h.Status.Conditions, "ControlPlaneBehind")
	}
	notChanging := func(what string, d time.Duration, want map[string]kri.State) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			for name, st := range want {
				if got := state(name); got != st {
					t.Fatalf("%s: %s is %s, want %s", what, name, got, st)
				}
			}
		}
	}

	// A control plane older than what this worker saw: the silo deleted there stays, and the
	// hold is reported.
	// Another control plane answers from now on: new connections, whose answers are judged
	// before anything in them is read.
	switchTo := func(seen client.ControlPlaneSeen) {
		cp.set(seen)
		ts.CloseClientConnections()
	}
	switchTo(client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 50})
	for deadline := time.Now().Add(10 * time.Second); !kept().Held; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("an older control plane, and not held: %+v", kept())
		}
	}
	if err := c.Delete(ctx, "Silo", "dev", "web"); err != nil {
		t.Fatal(err)
	}
	notChanging("held", 2*time.Second, map[string]kri.State{"web": kri.Running})
	if w := kept(); !w.Held || w.Revision != 100 {
		t.Fatalf("held, on disk: %+v", w)
	}
	if c := behind(); c == nil || c.Status != meta.ConditionTrue {
		t.Fatalf("held, and the Host doesn't say ControlPlaneBehind: %+v", c)
	}

	// A restart, the revision caught up: still held. A new silo isn't started.
	stop()
	cp.set(client.ControlPlaneSeen{ClusterID: "c1", History: "h1", Epoch: 1, Revision: 500})
	stop = start()
	e.place(t, "new", "hv1", nil)
	notChanging("held after a restart and a revision caught up", 2*time.Second, map[string]kri.State{"web": kri.Running, "new": kri.Absent})

	// Another cluster's control plane: ignored entirely.
	switchTo(client.ControlPlaneSeen{ClusterID: "c2", History: "x", Epoch: 1, Revision: 900})
	notChanging("another cluster", 1500*time.Millisecond, map[string]kri.State{"web": kri.Running, "new": kri.Absent})
	if w := kept(); w.ClusterID != "c1" {
		t.Fatalf("another cluster's answer was kept: %+v", w)
	}

	// A deliberate restore (a new history, epoch 2): accepted. The new silo starts; web, which
	// the restored state doesn't know and whose delete came from the held control plane, is kept.
	switchTo(client.ControlPlaneSeen{ClusterID: "c1", History: "h2", Epoch: 2, Revision: 10})
	for deadline := time.Now().Add(10 * time.Second); state("new") != kri.Running; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("not started after the new history: %s", state("new"))
		}
	}
	notChanging("after the new history", 1500*time.Millisecond, map[string]kri.State{"web": kri.Running, "new": kri.Running})
	if w := kept(); w.Held || w.History != "h2" || w.Epoch != 2 {
		t.Fatalf("after the new history, on disk: %+v", w)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if c := behind(); c != nil && c.Status == meta.ConditionFalse {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ControlPlaneBehind not cleared: %+v", behind())
		}
	}
	stop()
}
