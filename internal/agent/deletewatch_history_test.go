package agent_test

import (
	"os"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

// The delete watch stops when a new history is accepted. A delete that then arrives on the
// stream opened under the old history is not a delete seen here while this host trusts the new
// history. Coming back to the old history resumes the watch from the revision this host had
// reached, and that delete is still in the log, so the copy is removed.
func TestADeleteOnTheOldWatchIsSeenWhenThatHistoryIsTrustedAgain(t *testing.T) {
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
	r.waitFor("the delete still in this history's log is seen", func() bool {
		return !holds(r.t, r.rt, r.id.UID)
	})
}
