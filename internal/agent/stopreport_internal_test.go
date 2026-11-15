package agent

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// Rule 1: the agent reports a fenced stop only for the start the fence stopped. A start claim
// stored since (a start here that raced the report, or a cache that was behind) means another
// start, which the report would wrongly vouch for: nothing is written. A silo whose runtime says it
// runs again isn't reported either.
func TestAStopIsReportedOnlyForTheStartTheFenceStopped(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	opted := func(s *v1.Silo) { s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop }
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	claimed := func(name string, at time.Time) *v1.Silo {
		s := g.create(guardSilo(name, opted), "hv1", "")
		s.Status.Conditions = append(s.Status.Conditions, startClaim("hv1", s.Generation, at))
		if err := g.c.UpdateStatus(g.ctx, s); err != nil {
			t.Fatal(err)
		}
		s = g.stored(name)
		g.cacheIs(s)
		return s
	}
	stopped := func(s *v1.Silo, claim *meta.Condition) stoppedSilo {
		return stoppedSilo{t: fenceTarget{rt: g.rt, runtime: "docker", id: kri.ID{Namespace: "dev", Name: s.Name, UID: s.UID}, after: time.Minute}, claim: claim}
	}
	report := func(name string) *meta.Condition {
		return meta.FindCondition(g.stored(name).Status.Conditions, fence.ConditionStopped)
	}

	// The claim the fence stopped is the one stored: reported, for it.
	same := claimed("same", at)
	g.a.reportStopped(g.ctx, []stoppedSilo{stopped(same, standingClaim(same.Status))})
	if c, want := report("same"), fence.StoppedCondition("hv1", standingClaim(same.Status), same.Generation); c == nil || c.Message != want.Message {
		t.Fatalf("the stopped start: report %+v, want %+v", c, want)
	}

	// The fence stopped an earlier start (its claim older than the stored one): nothing written.
	newer := claimed("newer", at)
	older := startClaim("hv1", newer.Generation, at.Add(-time.Hour))
	g.a.reportStopped(g.ctx, []stoppedSilo{stopped(newer, &older)})
	if c := report("newer"); c != nil {
		t.Fatalf("a report for an earlier start was written: %+v", c)
	}

	// It runs again: nothing written.
	again := claimed("again", at)
	id := kri.ID{Namespace: "dev", Name: "again", UID: again.UID}
	if err := g.rt.Create(g.ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	if err := g.rt.Start(g.ctx, id); err != nil {
		t.Fatal(err)
	}
	g.a.reportStopped(g.ctx, []stoppedSilo{stopped(again, standingClaim(again.Status))})
	if c := report("again"); c != nil {
		t.Fatalf("a silo that runs again was reported stopped: %+v", c)
	}
}
