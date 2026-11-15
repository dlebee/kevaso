package agent

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	siloctl "kevaso.com/core/internal/controllers/silo"
)

// The control plane reads the agent's start claim (K-015): the host out of its message, and it
// keeps a claim fresh exactly as long as the agent means it to.
func TestTheControlPlaneReadsTheAgentsStartClaim(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "single", Namespace: "dev", UID: "u1", Generation: 3}}
	s.Status.Conditions = []meta.Condition{startClaim("metal-2", 3, time.Now().UTC())}
	host, id, ok := siloctl.StartClaimOf(s)
	if !ok || host != "metal-2" || id == "" {
		t.Fatalf("StartClaimOf: %q %q %v", host, id, ok)
	}
	if ConditionStartClaim != siloctl.CondStartClaim {
		t.Errorf("condition %q here, %q in the control plane", ConditionStartClaim, siloctl.CondStartClaim)
	}
	if StartClaimFresh != siloctl.StartClaimFresh {
		t.Errorf("a claim is fresh for %s here and %s in the control plane", StartClaimFresh, siloctl.StartClaimFresh)
	}
}
