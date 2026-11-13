package silo_test

import (
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// A Move silo handed off from hv1 to hv2, and hv2 lost before hv1 let go: hv1 may still run it
// and still has its volume mounted. Recreating it elsewhere must keep waiting for hv1. Clearing
// movingFrom let hv3 start it at once next to hv1's copy (a container without volumes), or left it
// waiting forever for a volume hv1 could no longer say it had unmounted.
func TestAMoveWhoseNewHostIsLostStillWaitsForTheOldOne(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	docker := func(h *v1.Host) *v1.Host {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		return h
	}
	s := newSilo("files")
	s.Spec.Runtime = "docker"
	s.Spec.Container = &v1.ContainerSource{Image: "app"}
	s.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "10Gi", MountPath: "/data"}}
	s.Spec.Availability.OnHostLoss = v1.OnHostLossMove
	s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv2", "hv1", "Scheduled"
	s.Status.Image = &v1.SiloImage{From: "app", Ref: "app:1", Running: "app:1"}
	s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
	hosts := []*v1.Host{docker(readyHost("hv1")), docker(lostHost("hv2", now.Add(-time.Minute))), docker(readyHost("hv3"))}
	hosts[0].Status.Allocatable = v1.Resources{} // full: it goes to hv3
	st, _, _, err := silo.DecideIn(s, hosts, nil, now, env)
	if err != nil {
		t.Fatal(err)
	}
	if st.Host != "hv3" {
		t.Fatalf("placed on %q", st.Host)
	}
	next := *s
	next.Status = st
	if moves.MayStart(&next, "hv3") {
		t.Fatalf("hv3 may start it while hv1 hasn't let go: %+v", st)
	}
	if _, ok := moves.Released(st, "hv1"); !ok {
		t.Fatalf("hv1 can no longer let go: %+v", st)
	}
	// Placed back on hv1 itself: nothing left to hand off (movingFrom would stay stuck, and
	// every later move be refused).
	back, _, _, err := silo.DecideIn(s, []*v1.Host{docker(readyHost("hv1")), docker(lostHost("hv2", now.Add(-time.Minute)))}, nil, now, env)
	if err != nil || back.Host != "hv1" || back.MovingFrom != "" {
		t.Fatalf("back on hv1: %+v %v", back, err)
	}
}
