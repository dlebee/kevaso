package agent_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// K-112: a handoff from this host read under another history than the one this host ran the silo
// under (a control plane restored from a backup taken while the silo moved away) is a replay, not
// an order: the copy, its root disk with it, is stopped and kept, never removed.
func TestAHandoffReadUnderANewHistoryStopsAndKeeps(t *testing.T) {
	r := newHistoryRig(t)
	r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	r.waitFor("it runs", func() bool { st, _ := r.rt.Status(r.ctx, r.id); return st.State == kri.Running })
	r.cp.switchTo(r.srvA, seenRestor) // a restore: a new history; the store says moving from hv1
	r.trusted(seenRestor)
	for {
		var cur v1.Silo
		if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &cur); err != nil {
			t.Fatal(err)
		}
		cur.Status.Host, cur.Status.MovingFrom = "hv2", "hv1"
		err := r.cA.UpdateStatus(r.ctx, &cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	r.waitFor("nothing of it runs on hv1", func() bool { return !r.w.RunsOn(r.id.UID, "hv1") })
	r.keptFor(r.id, 2*time.Second)
	r.listed(r.cA, r.id)
}
