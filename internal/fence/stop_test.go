package fence

import (
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// Brainstorm §0.7: a worker that loses the control plane stops nothing, except the silos that
// asked for it (onControlPlaneLoss: Stop), each after its own `after`. A record of version 2 says
// so per silo (StopAfter); onHostLoss means nothing to the fence any more, and neither does
// Applies (the silo asked to stop on a one-node cluster too: §0.7 says it stops every time).
func TestARecordOfVersion2StopsOnlyStopSilos(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	silo := func(name, policy string, after time.Duration) Silo {
		return Silo{ID: kri.ID{Namespace: "dev", Name: name, UID: "u-" + name}, Runtime: "docker", OnHostLoss: policy, StopAfter: after}
	}
	for _, applies := range []bool{false, true} {
		r := Record{Version: RecordVersion, LastContact: t0, Fence: applies, Silos: []Silo{
			silo("recreate", v1.OnHostLossRecreate, 0), silo("move", v1.OnHostLossMove, 0), silo("wait", v1.OnHostLossWait, 0),
			silo("stop2m", v1.OnHostLossRecreate, 2*time.Minute), silo("stop30s", v1.OnHostLossWait, 30*time.Second),
		}}
		for _, tc := range []struct {
			since time.Duration
			want  string
		}{
			{30 * time.Second, ""},
			{31 * time.Second, "stop30s"},
			{2 * time.Minute, "stop30s"},
			{2*time.Minute + time.Second, "stop2m,stop30s"},
			{48 * time.Hour, "stop2m,stop30s"},
		} {
			if got := stopNames(Decide(r, t0.Add(tc.since), DefaultAfter, nil)); got != tc.want {
				t.Errorf("Fence=%v, %v after the last contact: stopped %q, want %q", applies, tc.since, got, tc.want)
			}
		}
		if got := stopNames(Decide(r, t0.Add(time.Hour), DefaultAfter, map[string]bool{"u-stop2m": true})); got != "stop30s" {
			t.Errorf("already stopped ones again: %q", got)
		}
	}
	// No contact yet in this record: nothing (the agent counts from its own start, R-19).
	if got := Decide(Record{Version: RecordVersion, Silos: []Silo{silo("s", "", time.Minute)}}, t0, DefaultAfter, nil); got != nil {
		t.Fatalf("no contact yet: %v", got)
	}
	// A record from an agent before version 2 keeps its old meaning until the agent moves on.
	old := Record{LastContact: t0, Fence: true, Silos: []Silo{silo("recreate", v1.OnHostLossRecreate, 0)}}
	if got := stopNames(Decide(old, t0.Add(31*time.Second), DefaultAfter, nil)); got != "recreate" {
		t.Fatalf("a version 1 record: %q", got)
	}
}

func stopNames(ss []Silo) string {
	var n []string
	for _, s := range ss {
		n = append(n, s.ID.Name)
	}
	return strings.Join(n, ",")
}
