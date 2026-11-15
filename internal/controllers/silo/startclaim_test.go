package silo_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
)

// K-015, the control plane's half (control lane). A host starts a silo only after its start
// claim applied: condition "StartClaim" (agent.ConditionStartClaim), True, written by the host it
// is placed on, against the version it read. Only one of the claim and a restart elsewhere can
// apply (both write the silo); when the claim applied first, the control plane's write conflicts
// and it decides again on what is stored: it must not place the silo elsewhere while a claim of
// its host stands, younger than agent.StartClaimFresh (30s), whatever its own silence count says
// (the host is in contact: it just wrote).
func TestAFreshStartClaimKeepsTheSiloOnItsHost(t *testing.T) {
	t.Skip("K-015, control lane: restartsItself must leave a silo with a fresh StartClaim of its host where it is (see the comment); remove this skip with that change")
	s := newSilo("one")
	s.Generation = 3
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	s.Status.Host, s.Status.Phase = "hv1", "Starting"
	claimed := now.Add(-5 * time.Second)
	s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, 3),
		{Type: "StartClaim", Status: meta.ConditionTrue, Reason: "Starting", Message: "starting on hv1 at " + claimed.Format(time.RFC3339Nano),
			ObservedGeneration: 3, LastTransitionTime: claimed}}
	env := scheduler.Env{Silence: func(string) time.Duration { return time.Hour }} // by its own count, long silent
	hosts := []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}
	st, _, _, err := silo.DecideIn(s, hosts, nil, now, env)
	if err != nil {
		t.Fatal(err)
	}
	if st.Host != "hv1" {
		t.Fatalf("placed on %q while hv1's start claim of 5s ago stands: two copies", st.Host)
	}
}
