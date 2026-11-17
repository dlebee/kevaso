package controlplane

import (
	"context"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/worker"
)

// K-108, on a system node: its own heartbeat is its worker's fence contact. While that worker is
// held (its control plane is older than what it saw: this node's store rolled back, say), the
// heartbeat marks no fence contact, so the fence stops what asked to be stopped, as on a
// worker-only host; and it says so (Ready reason WorkerHeld), so it is no contact to the control
// plane either (stamp and Ready kept as stored): both count the same silence. A beat sent trusted
// whose answer finds the worker held marks no fence contact, and is the control plane's contact
// only: the safe side (the control plane counts less silence, never more).
func TestK108ASystemNodesHeartbeatIsNoContactWhileItsWorkerIsHeld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cp, admin, _ := k106Setup(ctx, t)
	cfg := Config{HostName: "hv1", InternalIP: "10.0.0.11", Clock: cp, Heartbeat: time.Hour, Log: t.Logf}
	// held answers, in turn, what the worker's judge says before the beat is sent and after.
	var mu sync.Mutex
	var says []bool
	held := func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(says) == 0 {
			return false
		}
		v := says[0]
		says = says[1:]
		return v
	}
	n := 0
	beat := func(before, after bool) (marked bool) {
		t.Helper()
		mu.Lock()
		says = []bool{before, after}
		mu.Unlock()
		n++
		var contact worker.Contact
		mark := string(rune('a' + n))
		bctx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			heartbeat(bctx, admin, cfg, selfReport{store: mark}, &contact, held)
		}()
		for {
			var h v1.Host
			_ = admin.Get(ctx, "Host", "", "hv1", &h)
			if h.Status.ControlPlane != nil && h.Status.ControlPlane.Store == mark {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("the heartbeat never landed")
			}
			time.Sleep(time.Millisecond)
		}
		// The write is in the store before the client has read its reply: cancelling now can end
		// the beat before it marks the contact. Give it until the contact is marked, or 300ms.
		for wait := time.Now().Add(300 * time.Millisecond); contact.Last().IsZero() && time.Now().Before(wait); {
			time.Sleep(time.Millisecond)
		}
		stop()
		<-done
		return !contact.Last().IsZero()
	}
	stored := func() *v1.Host {
		var h v1.Host
		if err := admin.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		return &h
	}
	contacts := hostctl.NewContacts(cp.Now())
	observe := func() time.Duration { contacts.Observe(stored(), cp.Now()); return contacts.Silence("hv1", cp.Now()) }

	if !beat(false, false) || observe() != 0 {
		t.Fatal("a trusted beat: no contact")
	}
	// Sent trusted, answered held: no fence contact; the control plane's contact (the safe side).
	cp.Step(time.Second)
	if beat(false, true) {
		t.Fatal("a beat answered while held marked the fence's contact")
	}
	if observe() != 0 {
		t.Fatal("a beat sent trusted: no contact to the control plane")
	}
	// Held, and marked lost by the host controller meanwhile.
	h := stored()
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost}}
	if err := admin.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	stamp := stored().Status.LastHeartbeat
	for i := range 3 {
		cp.Step(10 * time.Second)
		if beat(true, true) {
			t.Fatalf("held beat %d marked the fence's contact", i)
		}
		got := stored()
		if !got.Status.LastHeartbeat.Equal(*stamp) {
			t.Fatalf("held beat %d stored a new stamp", i)
		}
		if l, _ := hostctl.Lost(got); !l {
			t.Fatalf("held beat %d made the host ready again: %+v", i, meta.FindCondition(got.Status.Conditions, "Ready"))
		}
	}
	if s := observe(); s < 30*time.Second {
		t.Fatalf("the control plane counts %v of silence over 30s of held beats", s)
	}
	// Trusted again: a contact on both sides.
	cp.Step(10 * time.Second)
	if !beat(false, false) || observe() != 0 {
		t.Fatal("a trusted beat after the hold: no contact")
	}
	if l, _ := hostctl.Lost(stored()); l {
		t.Fatal("still lost after a trusted beat")
	}
}
