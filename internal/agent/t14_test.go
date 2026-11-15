package agent_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// forgets serves store to as it is, except a read of dev/single while lost is set, which empty
// answers (NotFound): a store read now that doesn't have the silo, with no delete of it made, while
// the worker's cache still holds it as it was (a restore, a system node behind, a re-made
// cluster). No DELETED event is sent: nothing is deleted.
type forgets struct {
	to, empty http.Handler
	lost      atomic.Bool
}

func (f *forgets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if f.lost.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/silos/single") {
		f.empty.ServeHTTP(w, r)
		return
	}
	f.to.ServeHTTP(w, r)
}

// T-14: invariant 2 at its point of use, mayRemove. The cache is stale (it has the silo placed on
// hv2, no handoff from here), the store read now has no such silo (NotFound), and no delete of it
// was seen: nothing is removed; the copy is kept, stopped, and listed on the Host. Answering
// "remove" on such a NotFound (the delete-seen rule made to always pass) must fail here.
func TestAStaleCacheAndAStoreWithoutTheSiloRemoveNothing(t *testing.T) {
	r := newHistoryRig(t)
	empty, _ := r.newStore()
	f := &forgets{to: r.srvA, empty: empty}
	r.cp.switchTo(f, seenA)
	r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	f.lost.Store(true)
	for { // placed elsewhere with no handoff: the cache follows; a read of it finds nothing
		var cur v1.Silo
		if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.Host = "hv2"
		err := r.cA.UpdateStatus(r.ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	r.waitFor("nothing of it runs on hv1", func() bool { return !r.w.RunsOn(r.id.UID, "hv1") })
	r.keptFor(r.id, 2*time.Second) // resyncs look again, each reading NotFound
	r.listed(r.cA, r.id)
}

// The outer keep in removeEverywhere: a copy the control plane never knew (the cache has nothing of
// that name, the store neither, no delete seen) keeps running, with its disk and volumes, and is
// listed. Without the keep it went on to mayRemove, which stops it.
func TestACopyTheControlPlaneDoesntKnowKeepsRunning(t *testing.T) {
	r := newHistoryRig(t)
	r.id = kri.ID{Namespace: "dev", Name: "single", UID: "0c0ffee0-0000-0000-0000-000000000000"}
	if err := r.rt.Create(r.ctx, kri.Spec{ID: r.id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := r.rt.Start(r.ctx, r.id); err != nil {
		t.Fatal(err)
	}
	r.start(r.rt)
	r.trusted(seenA)
	r.keptFor(r.id, 2*time.Second)
	if !r.w.RunsOn(r.id.UID, "hv1") {
		t.Fatal("a copy the control plane doesn't know, whose delete nobody saw, was stopped")
	}
	r.listed(r.cA, r.id)
	if !r.w.RunsOn(r.id.UID, "hv1") {
		t.Fatal("a copy the control plane doesn't know, whose delete nobody saw, was stopped")
	}
}

// The delete watch's held check: a delete event that comes while the worker is held (an answer
// from a system node behind was judged Hold, the stream opened before stays up) is no delete seen
// here. Once the hold ends, the silo is gone from the cache and the store, with no delete seen: its
// copy is kept and listed, never removed.
func TestADeleteThatComesWhileHeldIsNotSeen(t *testing.T) {
	r := newHistoryRig(t)
	stop := r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	// Answers are now judged Hold; the connections (the delete watch's stream) stay open.
	r.cp.mu.Lock()
	r.cp.seen = seenLag
	r.cp.mu.Unlock()
	r.waitFor("held", func() bool {
		b, _ := os.ReadFile(r.file)
		return strings.Contains(string(b), `"held":true`) && r.a.ControlPlaneHeld()
	})
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	r.keptFor(r.id, time.Second) // the event came, on the stream opened before the hold
	// The hold ends by a person's command (K-107: kvoadm host trust-control-plane sets the
	// watermark aside and restarts kevasod), and the worker trusts A again, the same history:
	// a delete recorded as seen during the hold would be honoured now.
	stop()
	if err := os.Remove(r.file); err != nil {
		t.Fatal(err)
	}
	r.cp.switchTo(r.srvA, seenA)
	r.start(r.rt)
	r.trusted(seenA)
	r.keptFor(r.id, 2*time.Second)
	if b, _ := os.ReadFile(filepath.Join(filepath.Dir(r.file), agent.SeenDeletesFile)); strings.Contains(string(b), r.id.UID) {
		t.Fatalf("a delete that came while held was recorded as seen: %s", b)
	}
	r.listed(r.cA, r.id)
}
