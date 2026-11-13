package moves

import (
	"errors"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

var classes = map[string]scheduler.Class{
	"linode-block": {Plugin: "linode", OwnHostsOnly: true, Topology: kplugin.TopologyRegion},
	"juicefs":      {Plugin: "juicefs", Topology: kplugin.TopologyGlobal},
	"vague":        {Plugin: "x"}, // says nothing: host-bound
}

func silo(rt string, policy string, vols ...v1.Volume) *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "web3", Name: "rpc-2"},
		Spec:   v1.SiloSpec{Runtime: rt, Volumes: vols, Availability: v1.Availability{OnHostLoss: policy}},
		Status: v1.SiloStatus{Host: "hv1"}}
}

func TestMovabilityIsTheNarrowestDisk(t *testing.T) {
	for _, tc := range []struct {
		name   string
		s      *v1.Silo
		data   bool
		scope  string
		pinned string
	}{
		{"vm: its own disk is local", silo("cloud-hypervisor", ""), false, "host", "disk root uses local on hv1"},
		{"vm with a global volume: still the local root", silo("cloud-hypervisor", "", v1.Volume{Name: "home", Class: "juicefs"}), false, "host", "disk root"},
		{"container, no volumes", silo("docker", ""), true, "global", ""},
		{"container on juicefs", silo("docker", "", v1.Volume{Name: "data", Class: "juicefs"}), true, "global", ""},
		{"container on linode-block and juicefs", silo("podman", "", v1.Volume{Name: "a", Class: "juicefs"}, v1.Volume{Name: "b", Class: "linode-block"}), true, "region", ""},
		{"a local volume pins it", silo("docker", "", v1.Volume{Name: "cache"}, v1.Volume{Name: "data", Class: "juicefs"}), false, "host", "volume cache uses local"},
		{"a class that doesn't say", silo("docker", "", v1.Volume{Name: "x", Class: "vague"}), false, "host", "volume x uses vague"},
		{"a class nobody serves", silo("docker", "", v1.Volume{Name: "x", Class: "gone"}), false, "host", "no plugin serves it"},
	} {
		m := Of(tc.s, classes)
		if m.WithData != tc.data || m.Scope != tc.scope || !strings.Contains(m.Pinned, tc.pinned) || (tc.pinned == "" && m.Pinned != "") {
			t.Errorf("%s: %+v", tc.name, m)
		}
	}
	vm := silo("cloud-hypervisor", "")
	vm.Spec.Disk.Class = "juicefs"
	if m := Of(vm, classes); !m.WithData || m.Scope != "global" {
		t.Errorf("vm with its disk on juicefs: %+v", m)
	}
}

func TestSummary(t *testing.T) {
	s := silo("docker", "", v1.Volume{Name: "b", Class: "linode-block"})
	s.Status.Volumes = []v1.VolumeStatus{{Name: "b", Region: "ca-central"}}
	for want, s := range map[string]*v1.Silo{
		"Anywhere":            silo("docker", "", v1.Volume{Name: "a", Class: "juicefs"}),
		"Region (ca-central)": s,
		"Recreate":            silo("cloud-hypervisor", v1.OnHostLossRecreate),
		"Pinned (hv1)":        silo("cloud-hypervisor", ""),
	} {
		if got := Summary(s, Of(s, classes)); got != want {
			t.Errorf("Summary = %q, want %q", got, want)
		}
	}
}

func TestCheckPolicy(t *testing.T) {
	if err := CheckPolicy(silo("cloud-hypervisor", v1.OnHostLossMove), Of(silo("cloud-hypervisor", ""), classes)); err == nil || !strings.Contains(err.Error(), "disk root uses local") {
		t.Fatalf("Move on a local disk: %v", err)
	}
	ok := silo("docker", v1.OnHostLossMove, v1.Volume{Name: "data", Class: "juicefs"})
	if err := CheckPolicy(ok, Of(ok, classes)); err != nil {
		t.Fatal(err)
	}
	imp := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "keys", Important: true})
	if err := CheckPolicy(imp, Of(imp, classes)); err == nil || !strings.Contains(err.Error(), "important volume keys") {
		t.Fatalf("Recreate with a local important volume: %v", err)
	}
	impGlobal := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "keys", Important: true, Class: "juicefs"})
	if err := CheckPolicy(impGlobal, Of(impGlobal, classes)); err != nil {
		t.Fatalf("an important volume that follows: %v", err)
	}
}

func TestPlanMove(t *testing.T) {
	movable := silo("docker", "", v1.Volume{Name: "data", Class: "juicefs"})
	m := Of(movable, classes)
	p, err := PlanMove(movable, m, Request{To: "hv3"}, false, "")
	if err != nil || !p.WithData || !p.Handoff || p.From != "hv1" || p.To != "hv3" {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	pinned := silo("cloud-hypervisor", "")
	for name, tc := range map[string]struct {
		s    *v1.Silo
		r    Request
		lost bool
		fits string
		want error
	}{
		"not placed":        {func() *v1.Silo { s := silo("docker", ""); s.Status.Host = ""; return s }(), Request{To: "hv3"}, false, "", ErrNotPlaced},
		"same host":         {movable, Request{To: "hv1"}, false, "", ErrSameHost},
		"pinned":            {pinned, Request{To: "hv3"}, false, "", ErrNotMovable},
		"recreate, Wait":    {pinned, Request{To: "hv3", Recreate: true}, false, "", ErrNoRecreate},
		"lost, unconfirmed": {movable, Request{To: "hv3"}, true, "", ErrNeedsFenced},
		"already moving":    {func() *v1.Silo { s := silo("docker", ""); s.Status.MovingFrom = "hv0"; return s }(), Request{To: "hv3"}, false, "", ErrMoving},
	} {
		if _, err := PlanMove(tc.s, Of(tc.s, classes), tc.r, tc.lost, tc.fits); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := PlanMove(movable, m, Request{To: "hv3"}, false, "runtime docker isn't installed"); err == nil || !strings.Contains(err.Error(), "hv3 can't take it: runtime docker") {
		t.Fatalf("target doesn't fit: %v", err)
	}
	// From a lost host, confirmed: no handoff (nobody is there to answer).
	p, err = PlanMove(movable, m, Request{To: "hv3", ConfirmFenced: true}, true, "")
	if err != nil || p.Handoff {
		t.Fatalf("confirmed move from a lost host = %+v, %v", p, err)
	}
	// Recreate: allowed for a Recreate silo, a fresh copy.
	rec := silo("cloud-hypervisor", v1.OnHostLossRecreate)
	p, err = PlanMove(rec, Of(rec, classes), Request{To: "hv3", Recreate: true}, false, "")
	if err != nil || p.WithData {
		t.Fatalf("recreate = %+v, %v", p, err)
	}
}

func TestApplyAndHandoff(t *testing.T) {
	s := silo("docker", "", v1.Volume{Name: "data", Class: "juicefs"})
	s.Status.Address, s.Status.Phase = "10.64.1.5", "Running"
	s.Status.Image = &v1.SiloImage{From: "app", Ref: "r1", Running: "r1"}
	st := Apply(s.Status, Plan{From: "hv1", To: "hv3", WithData: true, Handoff: true})
	if st.Host != "hv3" || st.MovingFrom != "hv1" || st.Address != "" || st.Phase != "Scheduled" || st.Image.Running != "r1" {
		t.Fatalf("with data: %+v", st)
	}
	moved := *s
	moved.Status = st
	if MayStart(&moved, "hv3") {
		t.Fatal("the new host started before the old one let go")
	}
	if MayStart(&moved, "hv1") {
		t.Fatal("the old host may not start it either")
	}
	if _, ok := Released(st, "hv3"); ok {
		t.Fatal("the new host released the handoff")
	}
	rel, ok := Released(st, "hv1")
	if !ok || rel.MovingFrom != "" {
		t.Fatalf("released = %+v", rel)
	}
	moved.Status = rel
	if !MayStart(&moved, "hv3") {
		t.Fatal("after the handoff the new host may start it")
	}
	fresh := Apply(s.Status, Plan{From: "hv1", To: "hv3"})
	if fresh.Image.Running != "" || s.Status.Image.Running != "r1" {
		t.Fatalf("recreate: %+v (input changed: %v)", fresh.Image, s.Status.Image.Running != "r1")
	}
}

func TestForceRelease(t *testing.T) {
	s := silo("docker", "")
	s.Status.Host = "hv3"
	vs := v1.VolumeStatus{Name: "data", AttachedTo: "hv1", Mounted: true}
	if !ForceRelease(s, vs, true) {
		t.Fatal("a lost, fenced host's mount should be released")
	}
	if ForceRelease(s, vs, false) {
		t.Fatal("a live host's mount is never forced")
	}
	s.Status.MovingFrom = "hv1"
	if ForceRelease(s, vs, true) {
		t.Fatal("forced while still waiting on hv1's handoff")
	}
}
