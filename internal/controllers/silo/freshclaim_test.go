package silo_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
)

// A start claim of the deleted host that is still fresh keeps the silo there. Once the claim
// is stale, the silo is placed, the same as a host delete with no claim.
func TestAFreshStartClaimKeepsASiloWhoseHostWasDeleted(t *testing.T) {
	env := scheduler.Env{}
	s := newSilo("web")
	s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	stamp := func(at time.Time) {
		t.Helper()
		meta.SetCondition(&s.Status.Conditions, meta.Condition{
			Type: moves.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting",
			Message: "starting on hv1 at " + at.UTC().Format(time.RFC3339),
		}, at)
		c := meta.FindCondition(s.Status.Conditions, moves.CondStartClaim)
		c.LastTransitionTime = at
	}
	hosts := []*v1.Host{asDocker(readyHost("hv2"))}

	stamp(now.Add(-5 * time.Second))
	st, _, again, err := silo.DecideIn(s, hosts, nil, now, env)
	if err != nil || st.Host != "hv1" || again <= 0 {
		t.Fatalf("a fresh claim: host %q again %v err %v", st.Host, again, err)
	}
	if c := meta.FindCondition(st.Conditions, moves.CondUnschedulable); c != nil && c.Reason == moves.ReasonHostDeleted {
		t.Fatalf("a fresh claim was marked %s", c.Reason)
	}

	stamp(now.Add(-time.Minute))
	st, _, _, err = silo.DecideIn(s, hosts, nil, now, env)
	if err != nil || st.Host != "hv2" {
		t.Fatalf("a stale claim: host %q err %v", st.Host, err)
	}
}
