package silo_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// onHostLoss: Move carries the silo's data to another host, so it is restarted elsewhere without a
// person only when every disk and volume can attach there. A silo with a disk on its host (class
// local) is never started elsewhere by the control plane, whatever else says it may: the data
// would be left behind and the old copy might still run. (Admission refuses the combination; this
// is the controller's own check for a silo written before that, or around it.)
func TestAMoveSiloWithAHostLocalDiskIsNeverRestartedElsewhere(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	margin := silo.StopMargin(45 * time.Second)
	env.Silence = func(string) time.Duration { return 45*time.Second + margin }
	hosts := []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}
	for _, tc := range []struct {
		class string
		moves bool
	}{{"", false}, {v1.VolumeLocal, false}, {"juicefs", true}} {
		s := newSilo("one")
		s.Generation = 3
		s.Spec.Disk.Class = tc.class
		s.Spec.Availability.OnHostLoss = v1.OnHostLossMove
		s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, 3)}
		confirmStopped(s, "hv1")
		st, _, _, err := silo.DecideIn(s, hosts, nil, now, env)
		if err != nil {
			t.Fatal(err)
		}
		if moved := st.Host == "hv2"; moved != tc.moves {
			t.Errorf("disk class %q: restarted on %q, want moved=%v", tc.class, st.Host, tc.moves)
		}
	}
}
