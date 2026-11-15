package moves

import (
	"errors"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
)

// Rule 1: the control plane restarts an opted-in silo elsewhere only once its host reported that
// its fence stopped it (FenceStopped). A host reports that only in its own name; a report it
// didn't write is not anyone else's to add (HostConditions).
func TestAHostReportsAFencedStopOnlyInItsOwnName(t *testing.T) {
	old := v1.SiloStatus{Host: "hv1", Phase: "Running"}
	for _, tc := range []struct {
		by string
		ok bool
	}{{"hv1", true}, {"hv2", false}, {"hv", false}} {
		next := old
		next.Conditions = []meta.Condition{fence.StoppedCondition(tc.by, nil, 1)}
		err := HostWrite(old, next, "hv1")
		if (err == nil) != tc.ok {
			t.Errorf("a report in %s's name: %v, want ok=%v", tc.by, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrHostWrite) {
			t.Errorf("%s: %v is not ErrHostWrite", tc.by, err)
		}
	}
	// One already there, unchanged: not this write's.
	stood := old
	stood.Conditions = []meta.Condition{fence.StoppedCondition("hv0", nil, 1)}
	next := stood
	next.Phase = "Starting"
	if err := HostWrite(stood, next, "hv1"); err != nil {
		t.Fatalf("an unchanged report: %v", err)
	}
	// Kept as stored against anyone but a host.
	forged := old
	forged.Conditions = []meta.Condition{fence.StoppedCondition("hv1", nil, 1)}
	if kept := KeepHostConditions(old, &forged); len(kept) != 1 || kept[0] != fence.ConditionStopped || len(forged.Conditions) != 0 {
		t.Fatalf("a non-host's report: kept %v, conditions %+v", kept, forged.Conditions)
	}
}
