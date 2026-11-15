package silo_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
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
//
// "Younger" is by the control plane's own count from when it first saw the claim
// (Env.StartClaimAge, kept in controllers/host.Contacts), never by the claim's timestamp, which
// is the agent's clock: so the claim's LastTransitionTime is set an hour off here, both ways, and
// changes nothing.
func TestAFreshStartClaimKeepsTheSiloOnItsHost(t *testing.T) {
	mk := func(claimedBy string, stamp time.Time) *v1.Silo {
		s := newSilo("one")
		s.Generation = 3
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
		s.Status.Host, s.Status.Phase = "hv1", "Starting"
		s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, 3)}
		if claimedBy != "" {
			s.Status.Conditions = append(s.Status.Conditions, meta.Condition{Type: "StartClaim", Status: meta.ConditionTrue, Reason: "Starting",
				Message: claimedBy + stamp.Format(time.RFC3339Nano), ObservedGeneration: 3, LastTransitionTime: stamp})
		}
		return s
	}
	const hv1 = "starting on hv1 at " // the agent's message, before its time
	hosts := []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}
	for _, c := range []struct {
		name      string
		claimedBy string        // the claim's message, before its time ("": no claim)
		stamp     time.Time     // the claim's own time: the agent's clock
		seen      time.Duration // how long ago the control plane first saw it
		nilAge    bool          // no Env.StartClaimAge: nothing known of when it was seen
		stays     bool
	}{
		{"seen 5s ago", hv1, now.Add(-5 * time.Second), 5 * time.Second, false, true},
		{"seen 5s ago, its stamp an hour old", hv1, now.Add(-time.Hour), 5 * time.Second, false, true},
		{"seen 29s ago", hv1, now, 29 * time.Second, false, true},
		{"not seen before (a new leader)", hv1, now.Add(-time.Hour), 0, false, true},
		{"seen 30s ago, its stamp just now", hv1, now, 30 * time.Second, false, false},
		{"seen an hour ago", hv1, now, time.Hour, false, false},
		{"when it was seen is unknown", hv1, now.Add(-time.Hour), 0, true, true},
		{"a claim of another host (one it was on before)", "starting on hv3 at ", now, 0, false, false},
		{"a claim that doesn't say who wrote it, seen 5s ago", "someone ", now, 5 * time.Second, false, true},
		{"a claim that doesn't say who wrote it, seen 30s ago", "someone ", now, 30 * time.Second, false, false},
		{"no claim", "", now, 0, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := mk(c.claimedBy, c.stamp)
			env := scheduler.Env{Silence: func(string) time.Duration { return time.Hour }} // by its own count, long silent
			if !c.nilAge {
				env.StartClaimAge = func(*v1.Silo) time.Duration { return c.seen }
			}
			st, _, again, err := silo.DecideIn(s, hosts, nil, now, env)
			if err != nil {
				t.Fatal(err)
			}
			if c.stays {
				if st.Host != "hv1" {
					t.Fatalf("placed on %q while hv1's start claim stands: two copies", st.Host)
				}
				u := meta.FindCondition(st.Conditions, silo.CondHostUnreachable)
				if u == nil || !strings.Contains(u.Message, "claimed its start") {
					t.Fatalf("the condition doesn't say why it waits: %+v", u)
				}
				if !c.nilAge && again != silo.StartClaimFresh-c.seen {
					t.Fatalf("looks again in %v, want when the claim stops standing (%v)", again, silo.StartClaimFresh-c.seen)
				}
				return
			}
			if st.Host != "hv2" {
				t.Fatalf("still on %q: a claim that doesn't stand kept it there (silent for an hour by our count)", st.Host)
			}
		})
	}
}

// The control plane's names for the claim are the agent's (host lane): if one changes, this
// fails rather than the two halves silently missing each other.
func TestTheStartClaimIsTheAgentsCondition(t *testing.T) {
	if silo.CondStartClaim != agent.ConditionStartClaim || silo.StartClaimFresh != agent.StartClaimFresh {
		t.Fatalf("control plane %q/%v, agent %q/%v", silo.CondStartClaim, silo.StartClaimFresh, agent.ConditionStartClaim, agent.StartClaimFresh)
	}
	host, _, ok := silo.StartClaimOf(&v1.Silo{Status: v1.SiloStatus{Conditions: []meta.Condition{{Type: agent.ConditionStartClaim, Status: meta.ConditionTrue,
		Message: "starting on hv1 at " + now.Format(time.RFC3339Nano)}}}})
	if !ok || host != "hv1" {
		t.Fatalf("the agent's claim message reads as host %q (%v)", host, ok)
	}
}

// A silo handing off to hv1 (from hv0, which hasn't let go) whose destination went silent is
// placed elsewhere at once: hv1 never started it, since a host claims its start only once it may
// (moves.MayStart). Were a fresh claim of hv1 there anyway, that reasoning is wrong, and the silo
// stays.
func TestASilentDestinationWithAFreshClaimIsNotReplaced(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		s := newSilo("one")
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv1", "hv0", "Scheduled"
		if claimed {
			s.Status.Conditions = []meta.Condition{{Type: silo.CondStartClaim, Status: meta.ConditionTrue, Message: "starting on hv1 at " + now.Format(time.RFC3339Nano)}}
		}
		env := scheduler.Env{Silence: func(string) time.Duration { return time.Hour }, StartClaimAge: func(*v1.Silo) time.Duration { return 5 * time.Second }}
		st, _, _, err := silo.DecideIn(s, []*v1.Host{readyHost("hv0"), lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}, nil, now, env)
		if err != nil {
			t.Fatal(err)
		}
		if placed := st.Host != "hv1"; placed == claimed || claimed && st.MovingFrom != "hv0" {
			t.Fatalf("claimed=%v: on %q moving from %q", claimed, st.Host, st.MovingFrom)
		}
	}
}
