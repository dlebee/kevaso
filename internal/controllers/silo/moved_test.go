package silo_test

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/scheduler"
)

// A move's Moved condition ends once the silo runs again with no handoff left, whichever way it
// got there. It stayed at "moving … from A to B" for as long as the silo lived, also when the silo
// ran again on the host it was moving from.
func TestMovedConditionEndsWhenTheSiloRuns(t *testing.T) {
	moving := func(host, phase, movingFrom string) *v1.Silo {
		s := newSilo("web")
		s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
		s.Status.Host, s.Status.Phase, s.Status.MovingFrom = host, phase, movingFrom
		meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Moved", Status: meta.ConditionTrue, Reason: "Moving",
			Message: "moving with its data from hv2 to hv1"}, now)
		return s
	}
	hosts := []*v1.Host{asDocker(readyHost("hv1")), asDocker(readyHost("hv2"))}
	cases := []struct {
		name       string
		s          *v1.Silo
		reason     string
		message    string
		wantChange bool
	}{
		{"running on the target", moving("hv1", "Running", ""), "Moved", "moved with its data from hv2 to hv1", true},
		{"running back on the host it was moving from", moving("hv2", "Running", ""), "Moved", "move ended: running on hv2", true},
		{"still starting on the target", moving("hv1", "Scheduled", ""), "Moving", "moving with its data from hv2 to hv1", false},
		{"still handing off", moving("hv1", "Running", "hv2"), "Moving", "moving with its data from hv2 to hv1", false},
	}
	for _, c := range cases {
		st, changed, _, err := silo.DecideIn(c.s, hosts, nil, now, scheduler.Env{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		m := meta.FindCondition(st.Conditions, "Moved")
		if m == nil || m.Reason != c.reason || m.Message != c.message {
			t.Errorf("%s: Moved %+v, want %s %q", c.name, m, c.reason, c.message)
		}
		if c.wantChange && !changed {
			t.Errorf("%s: the ended move wasn't written (changed false)", c.name)
		}
	}
}
