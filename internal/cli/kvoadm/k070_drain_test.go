package kvoadm

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

// K-070 (host lane): a silo moving S → D whose source S hasn't let go. Draining D must not
// replace the handoff: DrainStatus would write movingFrom: D, the silo is placed on E, D (which
// never ran it) lets go at once, and E starts it while S still runs it. Drain must leave such a
// silo alone (and say so), and write every other silo through client.StartHandoff, which reads
// afresh and refuses a handoff under way at the version it writes.
func TestK070DrainLeavesAHandoffUnderWay(t *testing.T) {
	t.Skip("K-070: host lane to fix (DrainPlan skips silos in a handoff; hostDrain writes with client.StartHandoff); see control-4.md")
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "d", Name: "s", Generation: 1},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "D", "S", "Scheduled"
	move, _ := DrainPlan("D", []*v1.Silo{s})
	for _, m := range move {
		if err := moves.Replaces(m.Status, DrainStatus(m, "D", time.Now())); err != nil {
			t.Fatalf("drain of D rewrites the handoff S → D: %v", err)
		}
	}
}
