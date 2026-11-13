package moves

import (
	"errors"
	"slices"
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
	// A volume is kept data, no flag: Recreate is refused with any host-local volume, naming them.
	local := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "keys"}, v1.Volume{Name: "db", Class: v1.VolumeLocal}, v1.Volume{Name: "data", Class: "juicefs"})
	err := CheckPolicy(local, Of(local, classes))
	if err == nil || !strings.Contains(err.Error(), "leave volumes db, keys behind") || !strings.Contains(err.Error(), "on the silo's own disk instead") {
		t.Fatalf("Recreate with local volumes: %v", err)
	}
	one := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "keys"})
	if err := CheckPolicy(one, Of(one, classes)); err == nil || !strings.Contains(err.Error(), "leave volume keys behind") {
		t.Fatalf("Recreate with one local volume: %v", err)
	}
	hostClass := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "scratch", Class: "vague"})
	if err := CheckPolicy(hostClass, Of(hostClass, classes)); err == nil || !strings.Contains(err.Error(), "volume scratch") {
		t.Fatalf("Recreate with a host-bound plugin volume: %v", err)
	}
	// Volumes on a class that travels follow the silo: they never block Recreate.
	travels := silo("docker", v1.OnHostLossRecreate, v1.Volume{Name: "data", Class: "juicefs"}, v1.Volume{Name: "blk", Class: "linode-block"})
	if err := CheckPolicy(travels, Of(travels, classes)); err != nil {
		t.Fatalf("Recreate with volumes that follow: %v", err)
	}
	// kvo move --recreate follows the same rule.
	if _, err := PlanMove(one, Of(one, classes), Request{To: "hv3", Recreate: true}, false, ""); err == nil || !strings.Contains(err.Error(), "volume keys") {
		t.Fatalf("--recreate with a local volume: %v", err)
	}
	if p, err := PlanMove(travels, Of(travels, classes), Request{To: "hv3", Recreate: true}, false, ""); err != nil || p.WithData {
		t.Fatalf("--recreate with volumes that follow: %+v %v", p, err)
	}
	// MOVABLE stays truthful: a VM on its local disk with no volumes can only be recreated.
	vm := silo("cloud-hypervisor", v1.OnHostLossRecreate)
	if m := Of(vm, classes); CheckPolicy(vm, m) != nil || Summary(vm, m) != "Recreate" {
		t.Errorf("MOVABLE of a recreatable VM: %q %v", Summary(vm, m), CheckPolicy(vm, m))
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
	s.Status.SiloIP, s.Status.Phase = "10.64.1.5", "Running"
	s.Status.Image = &v1.SiloImage{From: "app", Ref: "r1", Running: "r1"}
	st := Apply(s.Status, Plan{From: "hv1", To: "hv3", WithData: true, Handoff: true})
	if st.Host != "hv3" || st.MovingFrom != "hv1" || st.SiloIP != "" || st.Phase != "Scheduled" || st.Image.Running != "r1" {
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
	// The old host's volumes are said unmounted in the same write: it may write nothing else of
	// a silo placed elsewhere (on real machines a move waited forever for "w1 to unmount it").
	st.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", AttachedTo: "hv1", Mounted: true}}
	rel, ok := Released(st, "hv1")
	if !ok || rel.MovingFrom != "" || rel.Volumes[0].Mounted || !st.Volumes[0].Mounted {
		t.Fatalf("released = %+v (input changed: %v)", rel, !st.Volumes[0].Mounted)
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

// The old host's writes during a handoff: unmount its own volumes (LetGo), then let go
// (Released, which also counts them unmounted). Nobody else's, and never from the new host.
func TestLetGoAndReleased(t *testing.T) {
	st := v1.SiloStatus{Host: "hv2", MovingFrom: "hv1", Phase: "Scheduled", Volumes: []v1.VolumeStatus{
		{Name: "data", AttachedTo: "hv1", Mounted: true}, {Name: "shared", AttachedTo: "hv2", Mounted: true}}}
	got, ok := LetGo(st, "hv1")
	if !ok || got.Volumes[0].Mounted || !got.Volumes[1].Mounted || got.MovingFrom != "hv1" || got.Phase != "Scheduled" {
		t.Fatalf("LetGo: %+v %v", got, ok)
	}
	if !st.Volumes[0].Mounted {
		t.Fatal("LetGo changed its argument's volumes")
	}
	rel, ok := Released(st, "hv1")
	if !ok || rel.MovingFrom != "" || rel.Volumes[0].Mounted || !rel.Volumes[1].Mounted {
		t.Fatalf("Released: %+v %v", rel, ok)
	}
	for _, host := range []string{"hv2", "hv3"} {
		if _, ok := LetGo(st, host); ok {
			t.Errorf("LetGo by %s", host)
		}
		if _, ok := Released(st, host); ok {
			t.Errorf("Released by %s", host)
		}
	}
}

// Who may write what of a silo's status, per volume: only the host a volume is attached to (or
// to be mounted on) changes its mounted flag; the old host of a move may clear its own and let
// go; the new host may only set its own; nobody else writes it.
func TestHostWrite(t *testing.T) {
	moving := v1.SiloStatus{Host: "hv2", MovingFrom: "hv1", Phase: "Scheduled", Volumes: []v1.VolumeStatus{
		{Name: "data", AttachedTo: "hv1", Mounted: true}, {Name: "new", AttachedTo: "hv2"}}}
	placed := v1.SiloStatus{Host: "hv2", Phase: "Running", Volumes: []v1.VolumeStatus{
		{Name: "data", AttachedTo: "hv2", Mounted: true}, {Name: "left", AttachedTo: "hv1", Mounted: true}, {Name: "none"}}}
	with := func(st v1.SiloStatus, f func(*v1.SiloStatus)) v1.SiloStatus {
		st.Volumes = slices.Clone(st.Volumes)
		f(&st)
		return st
	}
	mount := func(i int, m bool) func(*v1.SiloStatus) { return func(st *v1.SiloStatus) { st.Volumes[i].Mounted = m } }
	letGo, _ := LetGo(moving, "hv1")
	released, _ := Released(moving, "hv1")
	for _, c := range []struct {
		name      string
		old, next v1.SiloStatus
		host      string
		ok        bool
	}{
		{"new host sets its own volume mounted", moving, with(moving, mount(1, true)), "hv2", true},
		{"new host writes its phase", moving, with(moving, func(st *v1.SiloStatus) { st.Phase = "Starting" }), "hv2", true},
		{"new host clears the old host's mounted", moving, with(moving, mount(0, false)), "hv2", false},
		{"new host clears movingFrom", moving, with(moving, func(st *v1.SiloStatus) { st.MovingFrom = "" }), "hv2", false},
		{"new host re-attaches a volume to itself", moving, with(moving, func(st *v1.SiloStatus) { st.Volumes[0].AttachedTo = "hv2" }), "hv2", false},
		{"new host drops a volume", moving, with(moving, func(st *v1.SiloStatus) { st.Volumes = st.Volumes[1:] }), "hv2", false},
		{"old host unmounts (LetGo)", moving, letGo, "hv1", true},
		{"old host lets go (Released)", moving, released, "hv1", true},
		{"old host lets go after LetGo", letGo, released, "hv1", true},
		{"old host sets mounted", letGo, moving, "hv1", false},
		{"old host writes its phase", moving, with(moving, func(st *v1.SiloStatus) { st.Phase = "Stopped" }), "hv1", false},
		{"old host clears the new host's volume", with(moving, mount(1, true)), with(moving, func(st *v1.SiloStatus) { st.Volumes[0].Mounted, st.Volumes[1].Mounted = false, false }), "hv1", false},
		{"a third host clears mounted", moving, with(moving, mount(0, false)), "hv3", false},
		{"a third host writes its phase", placed, with(placed, func(st *v1.SiloStatus) { st.Phase = "Failed" }), "hv3", false},
		{"host clears its own volume", placed, with(placed, mount(0, false)), "hv2", true},
		{"host clears a volume still on a lost host", placed, with(placed, mount(1, false)), "hv2", false},
		{"host marks an unattached volume mounted", placed, with(placed, mount(2, true)), "hv2", false},
		{"host moves its silo", placed, with(placed, func(st *v1.SiloStatus) { st.Host = "hv9" }), "hv2", false},
		{"host starts a move", placed, with(placed, func(st *v1.SiloStatus) { st.MovingFrom = "hv2" }), "hv2", false},
	} {
		err := HostWrite(c.old, c.next, c.host)
		if (err == nil) != c.ok {
			t.Errorf("%s: allowed=%v, want %v (%v)", c.name, err == nil, c.ok, err)
		}
		if err != nil && !errors.Is(err, ErrHostWrite) {
			t.Errorf("%s: %v is not ErrHostWrite", c.name, err)
		}
	}
}
