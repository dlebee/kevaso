package moves

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func hostDeletedCond(msg string) meta.Condition {
	return meta.Condition{Type: CondUnschedulable, Status: meta.ConditionTrue, Reason: ReasonHostDeleted,
		Message: msg, LastTransitionTime: time.Unix(10, 0).UTC()}
}

// A host may write a silo back with Unschedulable/HostDeleted as it stood. Adding, dropping
// or changing that condition is refused.
func TestHostWriteKeepsHostDeleted(t *testing.T) {
	cond := hostDeletedCond("hv1 was deleted")
	old := v1.SiloStatus{Host: "hv1", Phase: "Running", Conditions: []meta.Condition{cond}}
	round := old
	round.Phase = "Starting"
	if err := HostWrite(old, round, "hv1"); err != nil {
		t.Fatalf("writing it back: %v", err)
	}
	dropped := round
	dropped.Conditions = nil
	if err := HostWrite(old, dropped, "hv1"); err == nil {
		t.Fatal("dropped Unschedulable/HostDeleted")
	}
	changed := old
	changed.Conditions = []meta.Condition{hostDeletedCond("cleared")}
	if err := HostWrite(old, changed, "hv1"); err == nil {
		t.Fatal("changed Unschedulable/HostDeleted")
	}
	plain := v1.SiloStatus{Host: "hv1", Phase: "Running"}
	added := plain
	added.Conditions = []meta.Condition{cond}
	if err := HostWrite(plain, added, "hv1"); err == nil {
		t.Fatal("added Unschedulable/HostDeleted")
	}
}
