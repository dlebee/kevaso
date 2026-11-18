package restore

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/moves"
)

var started = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func oldSilo(host string) *v1.Silo {
	created := started.Add(-time.Hour)
	return &v1.Silo{
		ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", UID: "u1", CreationTimestamp: &created},
		Status:     v1.SiloStatus{Host: host, Phase: "Running", SiloIP: "10.64.0.2"},
	}
}

func openGate() *v1.RestoreGate {
	return &v1.RestoreGate{Spec: v1.RestoreGateSpec{
		History: "h2", Started: started, NoHostsAdded: true, Required: []string{"hv1", "hv2"},
	}}
}

func holding(name string, copies ...v1.HostHeldCopy) *v1.Host {
	return &v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Status: v1.HostStatus{
		Copies: &v1.HostCopies{History: "h2", Reported: true, Held: copies},
	}}
}

func copyOf() v1.HostHeldCopy {
	return v1.HostHeldCopy{Namespace: "dev", Name: "web", UID: "u1", Running: true}
}

func TestSettleOneCopyIsPlacedThere(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.Conditions = []meta.Condition{{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Message: "starting on hv1"}}
	st, changed := Settle(s, openGate(), []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv2" || st.SiloIP != "" || st.Phase != "Scheduled" || st.MovingFrom != "" {
		t.Fatalf("one copy: %+v", st)
	}
	if meta.FindCondition(st.Conditions, moves.CondStartClaim) != nil {
		t.Fatalf("the old host's start claim stayed: %+v", st.Conditions)
	}
}

func TestSettleNoCopyKeepsTheStoredPlacement(t *testing.T) {
	st, changed := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv1"), holding("hv2")})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || st.SiloIP != "10.64.0.2" || len(st.Restore.Holders) != 0 {
		t.Fatalf("no copy: %+v", st)
	}
}

func TestSettleTwoCopiesFreezeAndKeepThePlacement(t *testing.T) {
	st, changed := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv2", copyOf()), holding("hv1", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreFrozen || st.Host != "hv1" || st.SiloIP != "10.64.0.2" {
		t.Fatalf("two copies: %+v", st)
	}
	if len(st.Restore.Holders) != 2 || st.Restore.Holders[0] != "hv1" || st.Restore.Holders[1] != "hv2" {
		t.Fatalf("holders: %+v", st.Restore.Holders)
	}
}

func TestSettleWaitsForAHostThatHasNotReported(t *testing.T) {
	st, changed := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv1")})
	if !changed || st.Restore.Phase != v1.RestorePending || st.Host != "hv1" {
		t.Fatalf("waiting: %+v", st)
	}
}

func TestSettleAConfirmedOffHostHoldsNothing(t *testing.T) {
	g := openGate()
	g.Spec.ConfirmedOff = []string{"hv2"}
	st, changed := Settle(oldSilo("hv1"), g, []*v1.Host{holding("hv1")})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" {
		t.Fatalf("confirmed off: %+v", st)
	}
}

func TestSettleAHostAddedSinceTheBackupMustReport(t *testing.T) {
	g := openGate()
	g.Spec.NoHostsAdded = false
	g.Spec.HostsAdded = []string{"hv9"}
	st, _ := Settle(oldSilo("hv1"), g, []*v1.Host{holding("hv1"), holding("hv2")})
	if st.Restore == nil || st.Restore.Phase != v1.RestorePending || st.Host != "hv1" {
		t.Fatalf("added host: %+v", st.Restore)
	}
}

func TestSettleWithoutAStatementSettlesNothing(t *testing.T) {
	g := openGate()
	g.Spec.NoHostsAdded = false
	st, changed := Settle(oldSilo("hv1"), g, []*v1.Host{holding("hv1"), holding("hv2")})
	if !changed || st.Restore.Phase != v1.RestorePending || st.Host != "hv1" {
		t.Fatalf("no statement: %+v", st)
	}
}

func TestSettleASiloCreatedInThisHistoryIsSettledAtOnce(t *testing.T) {
	s := oldSilo("hv1")
	s.CreationTimestamp = &started
	st, changed := Settle(s, openGate(), nil)
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" {
		t.Fatalf("new silo: %+v", st)
	}
}

func TestSettleAHandoffIsNotCleared(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.MovingFrom = "hv2"
	st, changed := Settle(s, openGate(), []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || st.MovingFrom != "hv2" {
		t.Fatalf("handoff: %+v", st)
	}
}

func TestSettleDoesNotDecideAgain(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreFrozen, Holders: []string{"hv1", "hv2"}}
	st, changed := Settle(s, openGate(), []*v1.Host{holding("hv1", copyOf()), holding("hv2")})
	if changed || st.Restore.Phase != v1.RestoreFrozen || st.Host != "hv1" {
		t.Fatalf("frozen again: changed=%v %+v", changed, st)
	}
	s.Status.Restore = &v1.SiloRestore{History: "h2", Phase: v1.RestoreSettled}
	s.Status.Host = "hv1"
	st, changed = Settle(s, openGate(), []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if changed || st.Host != "hv1" || st.Restore.Phase != v1.RestoreSettled {
		t.Fatalf("settled again: changed=%v %+v", changed, st)
	}
}

func TestACopyOfAnotherSiloDoesNotCount(t *testing.T) {
	other := copyOf()
	other.UID = "other"
	st, _ := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv1", other), holding("hv2")})
	if st.Restore.Phase != v1.RestoreSettled || len(st.Restore.Holders) != 0 || st.Host != "hv1" {
		t.Fatalf("other uid: %+v", st)
	}
}
