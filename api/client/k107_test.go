package client

import "testing"

// K-107: a same-history hold is a store rolled back under the worker (a healthy member never
// answers lower in one history), so it never ends by itself: not when that store's revision
// passes what was kept, not on any later answer of that history. Only a new history (a
// deliberate restore, kvoadm init --restore) ends it, or a person (kvoadm host
// trust-control-plane, the host lane's), who replaces what the worker kept.
func TestK107ASameHistoryHoldNeverEndsByItself(t *testing.T) {
	kept := Watermark{ClusterID: "c", History: "h", Epoch: 1, Revision: 1500}
	// The rolled-back store answers at 800: held.
	w, v := JudgeAnswer(kept, 1500, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 800})
	if v != Hold || !w.Held {
		t.Fatalf("below what was kept: %v %+v, want Hold", v, w)
	}
	// It goes on writing: at, then past, the revision kept. Still held, and what was kept stays.
	for _, rev := range []int64{1500, 1501, 9000} {
		for _, at := range []int64{0, 1500, rev} {
			got, v := JudgeAnswer(w, at, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: rev})
			if v != Hold || !got.Held || got.Revision != 1500 {
				t.Fatalf("held, an answer of the same history at %d (sent at %d): %v %+v, want Hold, still keeping 1500", rev, at, v, got)
			}
			if got, v = JudgeStamp(w, at, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: rev}, true); v != Hold || !got.Held {
				t.Fatalf("JudgeStamp, held, same history at %d: %v %+v, want Hold", rev, v, got)
			}
		}
	}
	// A new history (a deliberate restore) ends it.
	got, v := JudgeAnswer(w, 1500, ControlPlaneSeen{ClusterID: "c", History: "h2", Epoch: 2, Revision: 10})
	if v != NewHistory || got.Held || got.History != "h2" {
		t.Fatalf("a new history: %v %+v, want NewHistory and no hold", v, got)
	}
	// Not held, the same history is accepted as before.
	if got, v = JudgeAnswer(kept, 1500, ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 1600}); v != Accept || got.Held || got.Revision != 1600 {
		t.Fatalf("not held, above: %v %+v", v, got)
	}
}
