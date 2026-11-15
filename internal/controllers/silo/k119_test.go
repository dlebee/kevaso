package silo_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// K-119: a handoff waits for its source to let go. With the source gone (lost, or its Host
// removed), the handoff ends by itself only for a silo whose source armed its fence for it
// (onControlPlaneLoss: Stop, this generation) and that reported its fence stopped it (FenceStopped,
// for its standing start claim), once this control plane has heard nothing from the source for its
// `after` plus StopMargin, on its own count (Env.Silence). Silence alone never ends it: a fence
// whose kill failed can't say so. Otherwise it waits, and the SourceUnreachable condition says so and names
// the command that ends it (kvo move … --confirm-fenced), and, for an armed silo, when it ends by
// itself.
func TestK119AHandoffFromAGoneSourceEndsOnlyForAnArmedStopSilo(t *testing.T) {
	const after = 2 * time.Minute
	classes := map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}
	wait := after + silo.StopMargin(after)
	mk := func(opted bool, armedBy, stoppedBy string) *v1.Silo {
		s := newSilo("db")
		s.Spec.Disk.Class = "juicefs" // it moves with its data: ended with --confirm-fenced alone
		if opted {
			s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop // after: 2m (the default)
		}
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "D", "S", "Scheduled"
		if armedBy != "" {
			s.Status.Conditions = []meta.Condition{fence.ArmedCondition(armedBy, after, s.Generation)}
		}
		if stoppedBy != "" {
			confirmStopped(s, stoppedBy)
		}
		return s
	}
	env := func(silent time.Duration) scheduler.Env {
		return scheduler.Env{Classes: classes, Silence: func(h string) time.Duration {
			if h == "S" {
				return silent
			}
			return 0
		}}
	}
	cond := func(st v1.SiloStatus) *meta.Condition {
		return meta.FindCondition(st.Conditions, silo.CondSourceUnreachable)
	}
	command := "kvo move silo db -n dev --to D --confirm-fenced"
	// The command named ends it: the move handler's plan for it.
	if p, err := moves.PlanMove(mk(false, "", ""), moves.Of(mk(false, "", ""), classes), moves.Request{To: "D", ConfirmFenced: true}, false, true, ""); err != nil || p.From != "S" || p.To != "D" {
		t.Fatalf("the command named: %+v, %v", p, err)
	}
	sourceSets := map[string][]*v1.Host{
		"S lost":    {lostHost("S", now.Add(-time.Hour)), readyHost("D")},
		"S removed": {readyHost("D")},
	}
	for name, hosts := range sourceSets {
		// Armed by S, opted in: waits for after + margin of S's silence, then ends by itself.
		s := mk(true, "S", "S")
		st, changed, again, err := silo.DecideIn(s, hosts, nil, now, env(wait-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		c := cond(st)
		if st.MovingFrom != "S" || !changed || c == nil || c.Status != meta.ConditionTrue || !strings.Contains(c.Message, command) || !strings.Contains(c.Message, "ends by itself") {
			t.Fatalf("%s, armed, %v silent: movingFrom %q, %+v", name, wait-time.Second, st.MovingFrom, c)
		}
		if again <= 0 || again > time.Second {
			t.Errorf("%s, armed: looks again in %v, want within the second left", name, again)
		}
		st, changed, _, _ = silo.DecideIn(s, hosts, nil, now, env(wait))
		if c = cond(st); st.MovingFrom != "" || !changed || st.Host != "D" || c == nil || c.Status != meta.ConditionFalse || c.Reason != "HandoffEnded" {
			t.Fatalf("%s, armed, %v silent: movingFrom %q on %q, %+v, want the handoff ended", name, wait, st.MovingFrom, st.Host, c)
		}
		if moves.HandingOff(st) || !moves.MayStart(&v1.Silo{Status: st}, "D") {
			t.Fatalf("%s: D may not start it after the end: %+v", name, st)
		}

		for what, x := range map[string]*v1.Silo{
			"not opted in":                     mk(false, "S", "S"),
			"opted in, never armed":            mk(true, "", ""),
			"armed by the destination, not S":  mk(true, "D", "D"),
			"armed for an older generation":    func() *v1.Silo { s := mk(true, "S", "S"); s.Generation = 2; return s }(),
			"armed, its stop never reported":   mk(true, "S", ""),
			"armed, the stop reported by D":    mk(true, "S", "D"),
			"armed, but no count of S silence": nil,
		} {
			e := env(48 * time.Hour)
			if x == nil {
				x, e = mk(true, "S", "S"), scheduler.Env{Classes: classes}
			}
			st, _, _, err := silo.DecideIn(x, hosts, nil, now, e)
			if err != nil {
				t.Fatal(err)
			}
			c := cond(st)
			if st.MovingFrom != "S" || c == nil || c.Status != meta.ConditionTrue || !strings.Contains(c.Message, command) {
				t.Errorf("%s, %s: movingFrom %q, %+v, want still waiting, naming %q", name, what, st.MovingFrom, c, command)
			}
		}
	}
	// S back: the condition says so; the handoff goes on as usual (S lets go).
	s := mk(true, "S", "S")
	st, _, _, _ := silo.DecideIn(s, sourceSets["S lost"], nil, now, env(time.Second))
	s.Status = st
	st, changed, _, _ := silo.DecideIn(s, []*v1.Host{readyHost("S"), readyHost("D")}, nil, now.Add(time.Minute), env(0))
	if c := cond(st); !changed || st.MovingFrom != "S" || c == nil || c.Status != meta.ConditionFalse || c.Reason != "SourceBack" {
		t.Fatalf("S back: changed %v, movingFrom %q, %+v", changed, st.MovingFrom, c)
	}
	// A handoff from a live source says nothing.
	if st, _, _, _ := silo.DecideIn(mk(true, "S", "S"), []*v1.Host{readyHost("S"), readyHost("D")}, nil, now, env(0)); cond(st) != nil {
		t.Fatalf("a live source: %+v", cond(st))
	}
}
