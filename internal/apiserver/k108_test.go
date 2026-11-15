package apiserver_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
)

// K-108, the control plane's half: a held worker (it judged its control plane older than what it
// saw) counts none of its heartbeats as its fence's contact, and says so in each one (its Ready
// reason, WorkerHeld). Such a beat is no contact here either: its stamp and its Ready condition
// stay as stored, so this control plane counts the host silent, marks it lost after its lease, and
// may restart its opted-in silos once their fences have stopped them, as for any host out of
// contact. A beat that doesn't say so is a contact, as before (a worker from before this change
// still marks its fence's contact on every beat: counting all of them is the safe side).
func TestK108AHeldWorkersHeartbeatIsNoContact(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)
	stored := func() *v1.Host {
		t.Helper()
		var h v1.Host
		if err := e.admin.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
			t.Fatal(err)
		}
		return &h
	}
	beat := func(held bool) {
		t.Helper()
		var h v1.Host
		if err := worker.Get(e.ctx, "Host", "", "hv2", &h); err != nil {
			t.Fatal(err)
		}
		reason := "WorkerUp"
		if held {
			reason = hostctl.ReasonWorkerHeld
		}
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: reason}, time.Now())
		if err := worker.UpdateStatus(e.ctx, &h); err != nil {
			t.Fatalf("a heartbeat (held %v): %v", held, err)
		}
	}
	contacts := hostctl.NewContacts(time.Now())
	beat(false)
	contacts.Observe(stored(), time.Now())
	before := stored()
	// Marked lost by the host controller meanwhile.
	lost, _ := v1.Clone(before)
	lost.Status.Conditions = nil
	meta.SetCondition(&lost.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost}, time.Now())
	if err := e.admin.UpdateStatus(e.ctx, lost); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	for range 3 {
		beat(true)
		got := stored()
		contacts.Observe(got, time.Now())
		if got.Status.LastHeartbeat == nil || !got.Status.LastHeartbeat.Equal(*before.Status.LastHeartbeat) {
			t.Fatalf("a held worker's heartbeat stored a new stamp: %v, was %v", got.Status.LastHeartbeat, before.Status.LastHeartbeat)
		}
		if l, _ := hostctl.Lost(got); !l {
			t.Fatalf("a held worker's heartbeat made its host ready again: %+v", meta.FindCondition(got.Status.Conditions, "Ready"))
		}
	}
	if s := contacts.Silence("hv2", time.Now()); s < time.Since(t0) {
		t.Fatalf("the control plane counts %v of silence over %v of held beats", s, time.Since(t0))
	}
	// Trusted again: the next beat is a contact.
	beat(false)
	got := stored()
	contacts.Observe(got, time.Now())
	if got.Status.LastHeartbeat.Equal(*before.Status.LastHeartbeat) || contacts.Silence("hv2", time.Now()) > time.Second {
		t.Fatalf("a heartbeat after the hold ended is no contact: stamp %v", got.Status.LastHeartbeat)
	}
	if l, _ := hostctl.Lost(got); l {
		t.Fatal("still lost after a trusted heartbeat")
	}
}
