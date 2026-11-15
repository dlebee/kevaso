package agent

import (
	"path/filepath"
	"testing"

	"kevaso.com/core/api/client"
)

// K-107: a hold within one history (the store rolled back, then writing again) ends only on a new
// history (kvoadm init --restore) or a person's command (kvoadm host trust-control-plane): never
// by the rolled-back store's revision catching up with what this worker kept, which two workers
// reach at different times (a moved silo then runs on both). The hold is kept across a restart.
func TestASameHistoryHoldEndsOnlyOnANewHistory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "w.json")
	w := OpenWatermark(file, t.Logf)
	ans := func(w *Watermark, h string, epoch, rev int64) client.Verdict {
		return w.Judged(w.Sending(), client.ControlPlaneSeen{ClusterID: "c", History: h, Epoch: epoch, Revision: rev}, true)
	}
	ans(w, "h", 1, 1000)
	if v := ans(w, "h", 1, 800); v != client.Hold || !w.Held() {
		t.Fatalf("rolled back to 800: %s, held %v", v, w.Held())
	}
	for _, rev := range []int64{1000, 1001, 5000} {
		if v := ans(w, "h", 1, rev); v != client.Hold || !w.Held() {
			t.Fatalf("the rolled-back store at %d: %s (held %v): a same-history hold ended by itself", rev, v, w.Held())
		}
	}
	if again := OpenWatermark(file, t.Logf); !again.Held() {
		t.Fatal("the hold didn't survive a restart")
	}
	if v := ans(w, "h2", 2, 10); v != client.NewHistory || w.Held() {
		t.Fatalf("a new history (a deliberate restore): %s, held %v", v, w.Held())
	}
}
