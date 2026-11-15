package silo_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
)

// stoppedBy is what host's agent writes once its fence stopped s and the runtime confirmed it:
// FenceStopped for the start claim s carries now (call it after the claim is set).
func stoppedBy(s *v1.Silo, host string) meta.Condition {
	var claim *meta.Condition
	if c := meta.FindCondition(s.Status.Conditions, silo.CondStartClaim); c != nil && c.Status == meta.ConditionTrue {
		claim = c
	}
	return fence.StoppedCondition(host, claim, s.Generation)
}

// confirmStopped adds stoppedBy(s, host) to s.
func confirmStopped(s *v1.Silo, host string) {
	meta.SetCondition(&s.Status.Conditions, stoppedBy(s, host), now)
}

// stopSiloOn is an opted-in silo (onControlPlaneLoss: Stop after 45s, onHostLoss: Recreate)
// placed on hv1, armed there, that hv1 started under a claim an hour ago.
func stopSiloOn() *v1.Silo {
	s := newSilo("one")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, s.Generation), claim("hv1", now.Add(-time.Hour))}
	return s
}

func decideSilent(t *testing.T, s *v1.Silo, silent time.Duration) v1.SiloStatus {
	t.Helper()
	env := scheduler.Env{Silence: func(string) time.Duration { return silent }, StartClaimAge: func(*v1.Silo) time.Duration { return time.Hour }}
	st, _, _, err := silo.DecideIn(s, []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}, nil, now, env)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// Rule 1, the owner's "wait for confirmation": silence alone, however long, never starts another
// copy; the condition says it waits for the host to confirm the stop, and names the person's
// command meanwhile.
func TestAStopSiloWaitsForItsHostToConfirmTheStop(t *testing.T) {
	s := stopSiloOn()
	st := decideSilent(t, s, 1000*time.Hour)
	if st.Host != "hv1" {
		t.Fatalf("restarted on %q with no report from hv1 that its copy stopped", st.Host)
	}
	u := meta.FindCondition(st.Conditions, silo.CondHostUnreachable)
	if u == nil || u.Status != meta.ConditionTrue || !strings.Contains(u.Message, "waits for hv1 to confirm") ||
		!strings.Contains(u.Message, "kvo move silo one -n dev --to HOST --confirm-fenced --recreate") {
		t.Fatalf("the condition doesn't say it waits for hv1, nor the person's command: %+v", u)
	}
}

// Once hv1 reported that its fence stopped this very start, the restart elsewhere proceeds
// (after the silence and margin, as before).
func TestAConfirmedStopLetsTheSiloRestartElsewhere(t *testing.T) {
	s := stopSiloOn()
	confirmStopped(s, "hv1")
	if st := decideSilent(t, s, 45*time.Second); st.Host != "hv1" {
		t.Fatalf("restarted on %q before the silence plus margin", st.Host)
	}
	st := decideSilent(t, s, 45*time.Second+silo.StopMargin(45*time.Second))
	if st.Host != "hv2" {
		t.Fatalf("confirmed stopped by hv1 and silent long enough: still on %q", st.Host)
	}
	if c := meta.FindCondition(st.Conditions, silo.CondFenceStopped); c != nil {
		t.Fatalf("hv1's report stays on the silo placed on hv2: %+v", c)
	}
}

// A report of an earlier placement or start never authorizes a restart: one for an older start
// claim (hv1 started it again since), one by another host, one for an older spec with no claim,
// one that isn't True.
func TestAStaleStopConfirmationDoesNotLetTheSiloRestart(t *testing.T) {
	long := 1000 * time.Hour
	for name, stale := range map[string]func(*v1.Silo){
		"an older start claim": func(s *v1.Silo) {
			old := stopSiloOn()
			old.Status.Conditions = []meta.Condition{claim("hv1", now.Add(-2*time.Hour))}
			meta.SetCondition(&s.Status.Conditions, stoppedBy(old, "hv1"), now)
		},
		"another host's": func(s *v1.Silo) { confirmStopped(s, "hv0") },
		"an older spec, no claim": func(s *v1.Silo) {
			s.Generation = 2 // armed for generation 2, no claim; the report is of generation 1
			s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, 2), fence.StoppedCondition("hv1", nil, 1)}
		},
		"not True": func(s *v1.Silo) {
			c := stoppedBy(s, "hv1")
			c.Status = meta.ConditionFalse
			meta.SetCondition(&s.Status.Conditions, c, now)
		},
	} {
		s := stopSiloOn()
		stale(s)
		if st := decideSilent(t, s, long); st.Host != "hv1" {
			t.Errorf("%s: restarted on %q on a stale report", name, st.Host)
		}
	}
	// The same silo with a report of its standing claim does restart: the cases above fail on
	// the report alone.
	s := stopSiloOn()
	confirmStopped(s, "hv1")
	if st := decideSilent(t, s, long); st.Host != "hv2" {
		t.Fatalf("a current report: still on %q", st.Host)
	}
}
