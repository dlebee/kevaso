package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// The delete watch stops when a new history is accepted. A delete that then arrives on the
// stream opened under the old history is not a delete seen here, including after a restart that
// trusts the old history again.
func TestADeleteOnTheOldWatchIsNotSeenAfterANewHistory(t *testing.T) {
	r := newHistoryRig(t)
	stop := r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool {
		st, _ := r.rt.Status(r.ctx, r.id)
		return st.State == kri.Running
	})
	// The watch stays open: only the stamp changes, so the next answer is a new history.
	r.cp.mu.Lock()
	r.cp.seen = seenRestor
	r.cp.mu.Unlock()
	r.trusted(seenRestor)
	if err := r.cA.Delete(r.ctx, "Silo", "dev", "single"); err != nil {
		t.Fatal(err)
	}
	r.keptFor(r.id, time.Second)
	stop()
	if err := os.Remove(r.file); err != nil {
		t.Fatal(err)
	}
	r.cp.switchTo(r.srvA, seenA)
	r.start(r.rt)
	r.trusted(seenA)
	r.keptFor(r.id, 2*time.Second)
	if b, _ := os.ReadFile(filepath.Join(filepath.Dir(r.file), agent.SeenDeletesFile)); strings.Contains(string(b), r.id.UID) {
		t.Fatalf("a delete from the old history's watch was recorded as seen: %s", b)
	}
	r.listed(r.cA, r.id)
}
