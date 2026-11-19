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
	return &v1.Host{
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec:       v1.HostSpec{Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}},
		Status: v1.HostStatus{
			Copies: &v1.HostCopies{History: "h2", Reported: true, Held: copies},
		},
	}
}

func controlPlaneOnly(name string) *v1.Host {
	return &v1.Host{
		ObjectMeta: meta.ObjectMeta{Name: name},
		Spec:       v1.HostSpec{Components: v1.HostComponents{ControlPlane: &v1.ControlPlaneSpec{}}},
	}
}

func copyOf() v1.HostHeldCopy {
	return v1.HostHeldCopy{Namespace: "dev", Name: "web", UID: "u1", Running: true}
}

func TestSettleOneCopyIsPlacedThere(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.Conditions = []meta.Condition{{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Message: "starting on hv1"}}
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Handle: "vol-1", AttachedTo: "hv2", Mounted: true}}
	st, changed := Settle(s, openGate(), []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv2" || st.SiloIP != "" || st.Phase != "Scheduled" || st.MovingFrom != "" {
		t.Fatalf("one copy the records already name: %+v", st)
	}
	if meta.FindCondition(st.Conditions, moves.CondStartClaim) != nil {
		t.Fatalf("the old host's start claim stayed: %+v", st.Conditions)
	}
	if st.Volumes[0].Handle != "vol-1" || st.Volumes[0].AttachedTo != "hv2" {
		t.Fatalf("volume: %+v", st.Volumes)
	}
}

func TestSettleNoCopyKeepsTheStoredPlacement(t *testing.T) {
	st, changed := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv1"), holding("hv2")})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || st.SiloIP != "10.64.0.2" || len(st.Restore.Holders) != 0 {
		t.Fatalf("no copy: %+v", st)
	}
}

func TestSettleTwoCopiesFreezeAndKeepThePlacement(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", AttachedTo: "hv2", Mounted: true}}
	st, changed := Settle(s, openGate(), []*v1.Host{holding("hv2", copyOf()), holding("hv1", copyOf())})
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

func TestSettleAControlPlaneWithNoWorkerCountsAsReported(t *testing.T) {
	g := openGate()
	g.Spec.Required = []string{"cp", "hv1"}
	st, changed := Settle(oldSilo("hv1"), g, []*v1.Host{controlPlaneOnly("cp"), holding("hv1")})
	if !changed || st.Restore == nil || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" {
		t.Fatalf("no report from the control plane: %+v changed=%v", st.Restore, changed)
	}
	cp := controlPlaneOnly("cp")
	cp.Status.Copies = &v1.HostCopies{History: "h2", Reported: true, Held: []v1.HostHeldCopy{copyOf()}}
	st, _ = Settle(oldSilo("hv1"), g, []*v1.Host{cp, holding("hv1")})
	if st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || len(st.Restore.Holders) != 0 {
		t.Fatalf("a control plane's copy list is not a holder: %+v", st.Restore)
	}
}

func TestAReportTheRecordsDoNotAllowDoesNotMovePlacement(t *testing.T) {
	g := openGate()
	g.Spec.Required = []string{"hv1", "bad"}
	g.Spec.ConfirmedOff = []string{"hv1"}
	st, changed := Settle(oldSilo("hv1"), g, []*v1.Host{holding("bad", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || len(st.Restore.Holders) != 0 {
		t.Fatalf("a host the backup does not name took the silo: %+v", st)
	}
	g = openGate()
	st, _ = Settle(oldSilo("hv1"), g, []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if st.Restore.Phase != v1.RestoreFrozen || st.Host != "hv1" || st.SiloIP != "10.64.0.2" {
		t.Fatalf("a report moved a silo off its live host: %+v", st)
	}
	g.Spec.NoHostsAdded = false
	g.Spec.HostsAdded = []string{"hv9"}
	st, _ = Settle(oldSilo("hv1"), g, []*v1.Host{holding("hv1"), holding("hv2"), holding("hv9", copyOf())})
	if st.Restore.Phase != v1.RestoreFrozen || st.Host != "hv1" {
		t.Fatalf("a host added since the backup moved a live host's silo: host %s phase %s", st.Host, st.Restore.Phase)
	}
}

func TestAStrangerClaimDoesNotFreezeTheStoredHost(t *testing.T) {
	st, changed := Settle(oldSilo("hv1"), openGate(), []*v1.Host{holding("hv1", copyOf()), holding("hv2", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv1" || len(st.Restore.Holders) != 1 || st.Restore.Holders[0] != "hv1" {
		t.Fatalf("a second claim froze the silo: %+v", st.Restore)
	}
}

func TestSettleFollowsVolumesOntoTheHolder(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "linode-block", Handle: "vol-1", AttachedTo: "hv1", Device: "/dev/sdb", Mounted: true}}
	g := openGate()
	g.Spec.ConfirmedOff = []string{"hv1"}
	g.Spec.NoHostsAdded = false
	g.Spec.HostsAdded = []string{"hv9"}
	st, changed := Settle(s, g, []*v1.Host{holding("hv2"), holding("hv9", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreSettled || st.Host != "hv9" || st.MovingFrom != "" {
		t.Fatalf("placed: %+v", st)
	}
	if len(st.Volumes) != 1 || st.Volumes[0].Handle != "vol-1" || st.Volumes[0].AttachedTo != "hv1" || st.Volumes[0].Mounted {
		t.Fatalf("volume was destroyed or left mounted: %+v", st.Volumes)
	}
	s.Status.Volumes = []v1.VolumeStatus{
		{Name: "data", Handle: "vol-1", AttachedTo: "hv1", Mounted: true},
		{Name: "extra", Handle: "vol-2", AttachedTo: "hv2", Mounted: true},
	}
	st, _ = Settle(s, openGate(), []*v1.Host{holding("hv1"), holding("hv2", copyOf())})
	if st.Restore.Phase != v1.RestoreSettled || st.Host != "hv2" || st.MovingFrom != "hv1" {
		t.Fatalf("live old host: host %s movingFrom %q phase %s", st.Host, st.MovingFrom, st.Restore.Phase)
	}
	if st.Volumes[0].Mounted != true || st.Volumes[0].Handle != "vol-1" || st.Volumes[1].Handle != "vol-2" {
		t.Fatalf("volumes: %+v", st.Volumes)
	}
}

func TestAHandoffWhoseOnlyCopyIsNeitherEndFreezes(t *testing.T) {
	s := oldSilo("hv1")
	s.Status.MovingFrom = "hv2"
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Handle: "vol-1", AttachedTo: "hv3", Mounted: true}}
	g := openGate()
	g.Spec.Required = []string{"hv1", "hv2", "hv3"}
	st, changed := Settle(s, g, []*v1.Host{holding("hv1"), holding("hv2"), holding("hv3", copyOf())})
	if !changed || st.Restore.Phase != v1.RestoreFrozen || st.Host != "hv1" || st.MovingFrom != "hv2" {
		t.Fatalf("third host: %+v movingFrom %q", st.Restore, st.MovingFrom)
	}
	if st.Volumes[0].Handle != "vol-1" {
		t.Fatalf("volume: %+v", st.Volumes)
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
