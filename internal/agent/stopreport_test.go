package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// reports serves the API and keeps every silo status write that carries a FenceStopped
// condition, as sent.
type reports struct {
	h    http.Handler
	mu   sync.Mutex
	sent []v1.SiloStatus
}

func (r *reports) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/status") {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		var s v1.Silo
		if json.Unmarshal(b, &s) == nil && meta.FindCondition(s.Status.Conditions, fence.ConditionStopped) != nil {
			r.mu.Lock()
			r.sent = append(r.sent, s.Status)
			r.mu.Unlock()
		}
	}
	r.h.ServeHTTP(w, req)
}

func (r *reports) all() []v1.SiloStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]v1.SiloStatus(nil), r.sent...)
}

// fencedReporting is fenced (an agent cut off on demand, every silo stopping after 1s) whose API
// writes are watched for stop reports.
func fencedReporting(t *testing.T) (*k088, *atomic.Bool, *reports) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	r := &reports{h: srv}
	ts := httptest.NewServer(r)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	w := fake.NewWorld()
	rt := fake.NewStrict("hv1", w)
	a := &agent.Agent{Client: client.New(ts.URL), HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	k := &k088{t: t, ctx: ctx, c: c, rt: rt, w: w, a: a}
	var cut atomic.Bool
	k.a.LastContact = func() time.Time {
		if cut.Load() {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}
	k.a.StopsOnLoss = func(*v1.Silo) (bool, time.Duration) { return true, time.Second }
	return k, &cut, r
}

// Rule 1, the host's half of "wait for confirmation": once contact is back, the agent reports on
// each silo its fence confirmed stopped that it did (FenceStopped), for the start claim it stopped,
// before it starts it again; and its next start's claim takes the report away (it no longer holds).
func TestAFencedStopIsReportedForTheStartItStopped(t *testing.T) {
	k, cut, r := fencedReporting(t)
	agent.RunForTest(t, k.ctx, k.a)
	k.place()
	k.waitFor("the silo runs", k.running)
	before := claimOf(k.get())
	if before == "" {
		t.Fatal("no start claim stored for the running silo")
	}
	cut.Store(true)
	k.waitFor("the fence stopped it", func() bool { return !k.running() })
	time.Sleep(1500 * time.Millisecond) // more passes: nothing is reported without contact
	if n := len(r.all()); n != 0 {
		t.Fatalf("%d stop reports written while cut off", n)
	}
	cut.Store(false)
	k.waitFor("hv1 reported the stop", func() bool { return len(r.all()) > 0 })
	st := r.all()[0]
	c := meta.FindCondition(st.Conditions, fence.ConditionStopped)
	claim := meta.FindCondition(st.Conditions, agent.ConditionStartClaim)
	if claim == nil || claim.Message != before {
		t.Fatalf("the report went with claim %+v, want the one stopped (%q)", claim, before)
	}
	if want := fence.StoppedCondition("hv1", claim, k.s.Generation); c.Status != meta.ConditionTrue || c.Message != want.Message || c.ObservedGeneration != want.ObservedGeneration {
		t.Fatalf("report %+v, want %+v", c, want)
	}
	k.waitFor("it runs again on hv1", k.running)
	k.waitFor("the new start's claim took the report away", func() bool {
		s := k.get()
		return claimOf(s) != before && meta.FindCondition(s.Status.Conditions, fence.ConditionStopped) == nil
	})
}

// A kill the runtime refuses is never reported stopped: the silo stays where it is (and the Host
// says the fence couldn't confirm it, K-094).
func TestAFenceKillThatFailedIsNeverReportedStopped(t *testing.T) {
	k, cut, r := fencedReporting(t)
	agent.RunForTest(t, k.ctx, k.a)
	k.place()
	k.waitFor("the silo runs", k.running)
	k.rt.RefuseKill(fake.ErrKillRefused)
	cut.Store(true)
	time.Sleep(3 * time.Second) // several passes
	cut.Store(false)
	time.Sleep(2 * time.Second) // contact back: the outage ends
	if !k.running() {
		t.Fatal("the refused kill stopped it anyway: the test doesn't test anything")
	}
	if n := len(r.all()); n != 0 {
		t.Fatalf("a silo whose kill failed was reported stopped (%d reports): %+v", n, r.all())
	}
}
