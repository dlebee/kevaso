package agent_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// holds says whether rt holds anything of the silo uid.
func holds(t *testing.T, rt kri.Runtime, uid string) bool {
	t.Helper()
	ids, err := rt.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.UID == uid {
			return true
		}
	}
	return false
}

// Found on the machines (metal.md, initcut2/slow): a container silo deleted while its init step
// ran. The delete, seen on this host's watch, must end the init step and remove the copy (its
// init and pause containers) at once, not at the start claim's next renewal, and not never.
// Renewals here are an hour apart: only the seen delete can end it.
func TestADeleteSeenDuringAnInitStepEndsItAndRemovesTheCopy(t *testing.T) {
	k := newK088(t, nil)
	k.a.ClaimRefresh = time.Hour
	k.rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return make(chan struct{}) } // until killed
	agent.RunForTest(t, k.ctx, k.a)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 300"})
	k.waitFor("the init step runs", func() bool { return k.rt.RunningInit(k.id) == "slow" })
	if err := k.c.Delete(k.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	k.waitFor("the init step ended on hv1", func() bool { return !k.w.RunsOn(k.id.UID, "hv1") })
	k.waitFor("its copy (init and pause containers, state) removed", func() bool { return !holds(t, k.rt, k.id.UID) })
}

// noWatch answers every watch with an error (lists work): the agent's delete watch never sees a
// delete, its silo cache follows by listing again.
type noWatch struct{ h http.Handler }

func (n noWatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("watch") == "true" {
		http.Error(w, "no watch here", http.StatusServiceUnavailable)
		return
	}
	n.h.ServeHTTP(w, r)
}

// The same, with the host's delete watch down: the start claim's renewal reading NotFound ends
// the start (nothing of it runs on), but is not a delete seen here (review-batch4 claim 1: a
// restore, or a system node behind, says the same of a silo nobody deleted). The copy is kept,
// stopped, with its data, as for any delete this host didn't see (K-068). Last night's version
// removed it.
func TestANotFoundAtTheClaimsRenewalEndsTheStartAndKeepsTheCopy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	blind := httptest.NewServer(noWatch{srv})
	t.Cleanup(func() { cancel(); blind.Close(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	w := fake.NewWorld()
	rt := fake.NewStrict("hv1", w)
	rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return make(chan struct{}) }
	a := &agent.Agent{Client: client.New(blind.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
		Log: t.Logf, ClaimRefresh: refresh}
	k := &k088{t: t, ctx: ctx, c: c, rt: rt, w: w, a: a}
	agent.RunForTest(t, ctx, a)
	k.place(v1.InitStep{Name: "slow", Run: "sleep 300"})
	k.waitFor("the init step runs", func() bool { return rt.RunningInit(k.id) == "slow" })
	if err := c.Delete(ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	k.waitFor("the init step ended on hv1", func() bool { return !w.RunsOn(k.id.UID, "hv1") })
	for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if !holds(t, rt, k.id.UID) {
			t.Fatal("a NotFound alone removed the copy")
		}
		if w.RunsOn(k.id.UID, "hv1") {
			t.Fatal("something of the abandoned start runs again")
		}
	}
}

// failDelete is the strict fake whose Delete fails while fail is set (a removal under way when
// kevasod stops: an engine that doesn't answer, a stop that takes long).
type failDelete struct {
	*fake.Strict
	fail atomic.Bool
}

func (f *failDelete) Delete(ctx context.Context, id kri.ID) error {
	if f.fail.Load() {
		return errors.New("the engine doesn't answer")
	}
	return f.Strict.Delete(ctx, id)
}

// A delete seen just before a restart, its removal not finished, is finished by the next run of
// the agent: it was seen here, and kept on disk before anything acted on it. A delete made while
// no agent ran is still never seen, and that copy is kept (design §0.7).
func TestADeleteSeenBeforeARestartIsFinishedAfterIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	w := fake.NewWorld()
	rt := &failDelete{Strict: fake.NewStrict("hv1", w)}
	file := filepath.Join(t.TempDir(), agent.SeenDeletesFile)
	newAgent := func() *agent.Agent {
		return &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{},
			Log: t.Logf, DeletesFile: file}
	}
	k := &k088{t: t, ctx: ctx, c: c, rt: rt.Strict, w: w}
	stop := agent.RunForTest(t, ctx, newAgent())
	k.place()
	gone := k.id
	k.waitFor("dev/single runs", func() bool { st, _ := rt.Status(ctx, gone); return st.State == kri.Running })
	other := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "other", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := c.Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	other.Status.Host, other.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, other); err != nil {
		t.Fatal(err)
	}
	otherID := kri.ID{Namespace: "dev", Name: "other", UID: other.UID}
	k.waitFor("dev/other runs", func() bool { st, _ := rt.Status(ctx, otherID); return st.State == kri.Running })

	rt.fail.Store(true) // its removal can't finish in this run
	if err := c.Delete(ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	k.waitFor("the delete is kept on disk", func() bool {
		b, _ := os.ReadFile(file)
		return strings.Contains(string(b), gone.UID)
	})
	time.Sleep(200 * time.Millisecond) // a removal tried, and failed
	stop()                             // kevasod restarts
	if !holds(t, rt, gone.UID) {
		t.Fatal("the copy went although its removal failed: the test shows nothing")
	}
	if err := c.Delete(ctx, "Silo", "dev", "other"); err != nil { // while no agent watches
		t.Fatal(err)
	}
	rt.fail.Store(false)
	agent.RunForTest(t, ctx, newAgent())
	k.waitFor("the copy of the delete seen before the restart removed", func() bool { return !holds(t, rt, gone.UID) })
	k.waitFor("its entry forgotten", func() bool {
		b, _ := os.ReadFile(file)
		return !strings.Contains(string(b), gone.UID)
	})
	time.Sleep(500 * time.Millisecond)
	if !holds(t, rt, otherID.UID) {
		t.Fatal("a silo whose delete no agent saw was removed with its data")
	}
}
