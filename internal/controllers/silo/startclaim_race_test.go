package silo_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// claimWorld is K-015's setting: silo dev/db (onControlPlaneLoss: Stop after 45s, onHostLoss:
// Recreate, its fence armed) on hv1, which the host lease calls lost and from which the control
// plane has heard nothing for an hour by its own count; hv2 is ready. The control plane's
// silo controller is driven one reconcile at a time, each on caches filled right then (its
// read), and every status write it sends passes through beforeWrite first (between its read and
// its write). hv1's agent is played by claim, the agent's own compare-and-swap (internal/agent
// claimStart, host lane): read the stored silo, give up unless it may start there, write the
// condition against the version read.
type claimWorld struct {
	t        *testing.T
	ctx      context.Context
	clk      *clock.Fake
	admin    *client.Client // the agent's and the test's
	cp       *client.Client // the control plane's, through the hook
	contacts *hostctl.Contacts

	mu          sync.Mutex
	beforeWrite func()
	toldHv2     bool // a status write placing the silo on hv2 applied
}

func newClaimWorld(t *testing.T) *claimWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	srv, err := apiserver.New(store.NewMemory(0), clk)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	w := &claimWorld{t: t, ctx: ctx, clk: clk, admin: client.New(ts.URL), contacts: hostctl.NewContacts(clk.Now())}
	w.cp = client.New(ts.URL)
	w.cp.HTTP = &http.Client{Transport: hook{w}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}))
	stamp := t0
	for _, h := range []*v1.Host{lostHost("hv1", t0), readyHost("hv2")} {
		st := h.Status
		must(w.admin.Create(ctx, h))
		h.Status = st
		h.Status.LastHeartbeat = &stamp
		must(w.admin.UpdateStatus(ctx, h))
		w.contacts.Observe(h, clk.Now()) // the last heartbeat this control plane saw, at t0
	}
	s := newSilo("db")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	must(w.admin.Create(ctx, s))
	s.Status.Host, s.Status.Phase = "hv1", "Stopped" // hv1's fence stopped it when it lost us
	s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, s.Generation)}
	confirmStopped(s, "hv1") // …and reported it (a start claim since makes this report stale)
	must(w.admin.UpdateStatus(ctx, s))
	clk.Step(time.Hour) // silent for an hour by our count: far beyond 45s + StopMargin
	return w
}

// hook passes the control plane's requests on, running beforeWrite before its first status write
// of the silo, and noting whether a write placing it on hv2 applied.
type hook struct{ w *claimWorld }

func (h hook) RoundTrip(req *http.Request) (*http.Response, error) {
	write := req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/silos/db/status")
	var body []byte
	if write {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		h.w.mu.Lock()
		f := h.w.beforeWrite
		h.w.beforeWrite = nil
		h.w.mu.Unlock()
		if f != nil {
			f()
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if write && err == nil && resp.StatusCode/100 == 2 {
		var s v1.Silo
		if json.Unmarshal(body, &s) == nil && s.Status.Host == "hv2" {
			h.w.mu.Lock()
			h.w.toldHv2 = true
			h.w.mu.Unlock()
		}
	}
	return resp, err
}

// reconcile is one round of the control plane's silo controller (the leader's, sharing contacts
// with its host controller), on caches filled now. A conflict is what the engine retries.
func (w *claimWorld) reconcile() (engine.Result, error) {
	w.t.Helper()
	ctl := &silo.Controller{Client: w.cp, Silos: frozen(w.ctx, w.t, w.cp, "Silo"), Hosts: frozen(w.ctx, w.t, w.cp, "Host"), Clock: w.clk, Contacts: w.contacts}
	return ctl.Reconcile(w.ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "db"})
}

// settle reconciles until a round ends without a conflict, as the engine would.
func (w *claimWorld) settle() engine.Result {
	w.t.Helper()
	for range 10 {
		res, err := w.reconcile()
		if err == nil {
			return res
		}
		if !client.IsConflict(err) {
			w.t.Fatal(err)
		}
	}
	w.t.Fatal("kept conflicting")
	return engine.Result{}
}

// agentRead is hv1's agent reading the stored silo before its claim: nil if it may not start
// it there (placed elsewhere, handing off, being deleted).
func (w *claimWorld) agentRead() *v1.Silo {
	w.t.Helper()
	var cur v1.Silo
	if err := w.admin.Get(w.ctx, "Silo", "dev", "db", &cur); err != nil {
		w.t.Fatal(err)
	}
	if cur.DeletionTimestamp != nil || !moves.MayStart(&cur, "hv1") {
		return nil
	}
	return &cur
}

// agentClaim writes hv1's start claim against the version read, stamped on hv1's clock (here a
// day behind: it must not matter). It reports whether it applied: whether hv1 starts the silo.
func (w *claimWorld) agentClaim(cur *v1.Silo) bool {
	w.t.Helper()
	stamp := w.clk.Now().UTC().Add(-24 * time.Hour)
	var conds []meta.Condition
	for _, c := range cur.Status.Conditions {
		if c.Type != silo.CondStartClaim {
			conds = append(conds, c)
		}
	}
	conds = append(conds, meta.Condition{Type: silo.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting",
		Message: "starting on hv1 at " + stamp.Format(time.RFC3339Nano), ObservedGeneration: cur.Generation, LastTransitionTime: stamp.Truncate(time.Second)})
	cur.Status.Conditions = conds
	err := w.admin.UpdateStatus(w.ctx, cur)
	if client.IsConflict(err) {
		return false
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return true
}

func (w *claimWorld) stored() *v1.Silo {
	w.t.Helper()
	var s v1.Silo
	if err := w.admin.Get(w.ctx, "Silo", "dev", "db", &s); err != nil {
		w.t.Fatal(err)
	}
	return &s
}

// K-015, the whole interleaving: hv1 is cut off, the silo stopped there, and the control plane is
// about to restart it on hv2 (silent for an hour by its own count). hv1's contact returns and its
// agent claims the start, with its read and its write each before the control plane's read,
// between that read and its write, or after its write. In every ordering at most one of "hv1
// starts it" (its claim applied) and "hv2 is told to start it" (a write placing it there
// applied) happens; and here exactly one, so neither side is stuck. The control plane goes on
// deciding (its conflicts retried, and twice more over the next 25s) to show it doesn't place the
// silo elsewhere later either while the claim stands. Deterministic: no sleeps, one reconcile at a
// time.
func TestAStartClaimAndARestartElsewhereNeverBothHappen(t *testing.T) {
	const before, between, after, never = 0, 1, 2, 3
	point := []string{"before the control plane's read", "between its read and its write", "after its write", "never"}
	cases := [][2]int{{never, never}, {before, before}, {before, between}, {before, after}, {between, between}, {between, after}, {after, after}}
	for _, c := range cases {
		readAt, writeAt := c[0], c[1]
		t.Run(fmt.Sprintf("agent reads %s, writes %s", point[readAt], point[writeAt]), func(t *testing.T) {
			w := newClaimWorld(t)
			var cur *v1.Silo
			started, gaveUp := false, false
			agentAt := func(p int) {
				if readAt == p {
					if cur = w.agentRead(); cur == nil {
						gaveUp = true
					}
				}
				if writeAt == p && !gaveUp {
					started = w.agentClaim(cur)
				}
			}
			agentAt(before)
			w.beforeWrite = func() { agentAt(between) }
			res, err := w.reconcile() // the control plane's read, decision and write
			if err != nil && !client.IsConflict(err) {
				t.Fatal(err)
			}
			w.mu.Lock()
			missed := w.beforeWrite != nil // it never wrote
			w.beforeWrite = nil
			w.mu.Unlock()
			if missed {
				agentAt(between) // nothing was written: "between" is as good as after its read
			}
			agentAt(after)
			if err != nil || res.RequeueAfter > 0 {
				w.settle()
			}
			for range 2 { // and later, still within the claim's window
				w.clk.Step(12 * time.Second)
				w.settle()
			}
			w.mu.Lock()
			told := w.toldHv2
			w.mu.Unlock()
			s := w.stored()
			t.Logf("hv1 started it: %v; hv2 told to: %v; stored on %q", started, told, s.Status.Host)
			if started && told {
				t.Fatalf("two copies: hv1's claim applied and the silo was placed on hv2 (stored on %q)", s.Status.Host)
			}
			if !started && !told {
				t.Fatalf("neither started it (stored on %q, %+v)", s.Status.Host, s.Status.Conditions)
			}
			if started && s.Status.Host != "hv1" || told && s.Status.Host != "hv2" {
				t.Fatalf("stored on %q", s.Status.Host)
			}
		})
	}
}

// K-015 both ways, on the fake clock, with the real controller: a fresh claim of a host the
// control plane long counted as silent keeps the silo there, and is a contact (the silence count
// starts again from it); a claim left by a host that then really went silent doesn't pin the
// silo: once the claim is past its window and the count since it (its last contact) is past
// `after` plus the margin, the normal rule restarts it elsewhere, not a second earlier.
func TestAnOldStartClaimOfASilentHostDoesNotPinTheSilo(t *testing.T) {
	w := newClaimWorld(t)
	cur := w.agentRead()
	if cur == nil || !w.agentClaim(cur) {
		t.Fatal("hv1's claim didn't apply")
	}
	// hv1's fence then stopped that start, and hv1 said so before it went silent again.
	cur = w.stored()
	confirmStopped(cur, "hv1")
	if err := w.admin.UpdateStatus(w.ctx, cur); err != nil {
		t.Fatal(err)
	}
	wait := 45*time.Second + silo.StopMargin(45*time.Second) // 61s
	look := func(at time.Duration, want string, says string) {
		t.Helper()
		res := w.settle()
		s := w.stored()
		u := meta.FindCondition(s.Status.Conditions, silo.CondHostUnreachable)
		if s.Status.Host != want || u == nil || !strings.Contains(u.Message, says) {
			t.Fatalf("%v after the claim: on %q, %+v", at, s.Status.Host, u)
		}
		if want == "hv1" && res.RequeueAfter <= 0 {
			t.Fatalf("%v after the claim: waits without a time to look again", at)
		}
	}
	look(0, "hv1", "hv1 claimed its start")
	w.clk.Step(silo.StartClaimFresh - time.Second)
	look(silo.StartClaimFresh-time.Second, "hv1", "hv1 claimed its start")
	// Past the claim's window: the claim no longer counts, but it was a contact, so the silence
	// count runs from it.
	w.clk.Step(time.Second)
	look(silo.StartClaimFresh, "hv1", "30s so far")
	w.clk.Step(wait - silo.StartClaimFresh - time.Second)
	look(wait-time.Second, "hv1", "1m0s so far")
	w.clk.Step(time.Second)
	look(wait, "hv2", "silent for 1m1s")
}
