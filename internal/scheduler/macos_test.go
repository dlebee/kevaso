package scheduler

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// mac is a Mac worker: the tart runtime only, which Apple limits to two macOS guests at once.
func mac(name string) *v1.Host {
	h := host(name)
	h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "tart"}}
	h.Status.Runtimes = map[string]v1.RuntimeStatus{"tart": {State: "Ready", MaxSilos: 2}}
	return h
}

func TestMacSilosGoOnlyToAMac(t *testing.T) {
	d, err := Schedule(silo("ios", withRuntime("tart")), hosts(host("linux1"), mac("mini")), nil)
	if err != nil || d.Host != "mini" {
		t.Fatalf("%+v %v", d, err)
	}
	if why := d.Excluded["linux1"]; why != "runtime tart not installed" {
		t.Fatalf("linux host: %q", why)
	}
	// And a Linux silo never goes to the Mac.
	d, _ = Schedule(silo("web"), hosts(mac("mini"), host("linux1")), nil)
	if d.Host != "linux1" {
		t.Fatalf("%+v", d)
	}
}

func TestAMacTakesTwoMacSilosAtMost(t *testing.T) {
	two := placed(silo("a", withRuntime("tart"), on("mini")), silo("b", withRuntime("tart"), on("mini")))
	d, _ := Schedule(silo("c", withRuntime("tart")), hosts(mac("mini")), two)
	if d.Host != "" || d.Excluded["mini"] == "" {
		t.Fatalf("third macOS silo was placed: %+v", d)
	}
	// A second Mac takes it.
	d, _ = Schedule(silo("c", withRuntime("tart")), hosts(mac("mini"), mac("studio")), two)
	if d.Host != "studio" {
		t.Fatalf("%+v", d)
	}
	// Linux silos on the same worker don't use up the macOS ones (a host with both runtimes).
	h := mac("mini")
	h.Status.Runtimes["docker"] = v1.RuntimeStatus{State: "Ready"}
	h.Spec.Components.Worker.Runtimes = append(h.Spec.Components.Worker.Runtimes, v1.RuntimeSpec{Name: "docker"})
	mixed := placed(silo("a", withRuntime("tart"), on("mini")), silo("l1", withRuntime("docker"), on("mini")), silo("l2", withRuntime("docker"), on("mini")))
	if d, _ := Schedule(silo("c", withRuntime("tart")), hosts(h), mixed); d.Host != "mini" {
		t.Fatalf("%+v", d)
	}
	// A silo's own placed copy doesn't count against itself (rescheduling).
	if d, _ := Schedule(silo("a", withRuntime("tart")), hosts(mac("mini")), two); d.Host != "mini" {
		t.Fatalf("%+v", d)
	}
}

func TestNoLimitWhenTheRuntimeSaysNone(t *testing.T) {
	var ps []*v1.Silo
	for _, n := range []string{"a", "b", "c", "d"} {
		ps = append(ps, silo(n, on("hv1")))
	}
	if d, _ := Schedule(silo("e"), hosts(host("hv1", mem("64Gi"), func(h *v1.Host) { h.Status.Allocatable.CPU = 64 })), ps); d.Host != "hv1" {
		t.Fatalf("%+v", d)
	}
}
