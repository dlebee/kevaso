package silo_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

func asDocker(h *v1.Host) *v1.Host {
	h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
	h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
	return h
}

// A movable silo whose Host object is gone is placed on another host. One that is not stays
// in the store, unplaced, Unschedulable/HostDeleted. A handoff from the deleted host ends.
// Nothing in the status drops a volume.
func TestHostDeletePlacesWhatCanMoveAndKeepsTheRest(t *testing.T) {
	classes := map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}
	env := scheduler.Env{Classes: classes}

	t.Run("recreate", func(t *testing.T) {
		s := newSilo("web")
		s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		st, changed, _, err := silo.DecideIn(s, []*v1.Host{asDocker(readyHost("hv2"))}, nil, now, env)
		if err != nil || !changed || st.Host != "hv2" || st.Phase != silo.PhaseScheduled {
			t.Fatalf("placed %+v err %v", st, err)
		}
	})

	t.Run("move with data", func(t *testing.T) {
		s := newSilo("db")
		s.Spec.Disk.Class = "juicefs"
		s.Spec.Availability.OnHostLoss = v1.OnHostLossMove
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1"}}
		st, changed, _, err := silo.DecideIn(s, []*v1.Host{readyHost("hv2")}, nil, now, env)
		if err != nil || !changed || st.Host != "hv2" {
			t.Fatalf("placed %+v err %v", st, err)
		}
		if len(st.Volumes) != 1 || st.Volumes[0].Handle != "vol-1" {
			t.Fatalf("the volume was dropped: %+v", st.Volumes)
		}
	})

	t.Run("not movable", func(t *testing.T) {
		s := newSilo("pin")
		s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
		s.Spec.Volumes = []v1.Volume{{Name: "data", Class: v1.VolumeLocal, Size: "1Gi", MountPath: "/data"}}
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: v1.VolumeLocal, Handle: "local-1", AttachedTo: "hv1"}}
		st, changed, _, err := silo.DecideIn(s, []*v1.Host{asDocker(readyHost("hv2"))}, nil, now, env)
		c := meta.FindCondition(st.Conditions, moves.CondUnschedulable)
		if err != nil || !changed || st.Host != "hv1" || st.Host == "hv2" || c == nil || c.Status != meta.ConditionTrue || c.Reason != moves.ReasonHostDeleted {
			t.Fatalf("kept %+v err %v", st, err)
		}
		if !strings.Contains(c.Message, "hv1 was deleted") || !strings.Contains(c.Message, "kvo move silo pin -n dev --to HOST --recreate") || !strings.Contains(c.Message, "no longer reachable") || !strings.Contains(c.Message, "nothing deleted") {
			t.Fatalf("message %q", c.Message)
		}
		if len(st.Volumes) != 1 || st.Volumes[0].Handle != "local-1" {
			t.Fatalf("the volume was dropped: %+v", st.Volumes)
		}
		if moves.MayStart(&v1.Silo{Status: st}, "hv1") {
			t.Fatal("the deleted host's name may start it")
		}
		// Joining again under the same name does not clear it.
		again, changed, _, _ := silo.DecideIn(&v1.Silo{TypeMeta: s.TypeMeta, ObjectMeta: s.ObjectMeta, Spec: s.Spec, Status: st}, []*v1.Host{asDocker(readyHost("hv1")), asDocker(readyHost("hv2"))}, nil, now, env)
		if changed || again.Host != "hv1" || meta.FindCondition(again.Conditions, moves.CondUnschedulable).Reason != moves.ReasonHostDeleted {
			t.Fatalf("re-added: changed %v %+v", changed, again)
		}
	})

	t.Run("handoff ends", func(t *testing.T) {
		s := newSilo("move")
		s.Spec.Disk.Class = "juicefs"
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv2", "hv1", "Scheduled"
		st, changed, _, err := silo.DecideIn(s, []*v1.Host{readyHost("hv2")}, nil, now, env)
		c := meta.FindCondition(st.Conditions, silo.CondSourceUnreachable)
		if err != nil || !changed || st.Host != "hv2" || st.MovingFrom != "" || c == nil || c.Reason != "HandoffEnded" {
			t.Fatalf("handoff %+v err %v", st, err)
		}
		// The Host still exists and is only lost: the handoff does not end.
		lost := newSilo("move")
		lost.Spec.Disk.Class = "juicefs"
		lost.Status.Host, lost.Status.MovingFrom, lost.Status.Phase = "hv2", "hv1", "Scheduled"
		st, _, _, err = silo.DecideIn(lost, []*v1.Host{lostHost("hv1", now), readyHost("hv2")}, nil, now, env)
		if err != nil || st.MovingFrom != "hv1" || st.Host != "hv2" {
			t.Fatalf("lost, not deleted: %+v err %v", st, err)
		}
	})
}
