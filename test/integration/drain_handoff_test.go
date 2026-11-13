package integration

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
)

// kvoadm host drain moves a Recreate silo off a live host. Two copies must never run (design §0.3):
// the host it lands on may start it only once the old host has stopped it, as with kvo move.
// Drain writes the silo's status as hostDrain does, then the silo controller places it.
func TestDrainWaitsForTheOldHostToLetGo(t *testing.T) {
	hv := func(name string) *v1.Host {
		h := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{InternalIP: "10.0.0.5",
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
		return h
	}
	old, next := hv("hv1"), hv("hv2")
	old.Spec.Unschedulable = true // drain cordons it first
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "validator", Namespace: "web3", Generation: 1},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx:1.27"}, Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
	s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.1.2"
	move, _ := kvoadm.DrainPlan("hv1", []*v1.Silo{s})
	if len(move) != 1 {
		t.Fatalf("drain moves %d silos", len(move))
	}
	// What hostDrain writes (internal/cli/kvoadm/hosts.go).
	s.Status = kvoadm.DrainStatus(s, "hv1", time.Now())
	st, _, _, err := siloctl.Decide(s, []*v1.Host{old, next}, nil, time.Now())
	if err != nil || st.Host != "hv2" {
		t.Fatalf("placed on %q: %v", st.Host, err)
	}
	s.Status = st
	if moves.MayStart(s, "hv2") {
		t.Fatalf("hv2 may start the new copy while hv1 still runs the old one: %+v", s.Status)
	}
	// hv1's agent stops its copy and lets go; only then may hv2 start it.
	released, ok := moves.Released(s.Status, "hv1")
	if !ok {
		t.Fatalf("hv1 can't release it: %+v", s.Status)
	}
	s.Status = released
	if !moves.MayStart(s, "hv2") {
		t.Fatalf("released by hv1, yet hv2 may not start it: %+v", s.Status)
	}
}
