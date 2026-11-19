package provider_test

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

func blockVolume() v1.Volume {
	return v1.Volume{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}
}

func detachesSince(log []string, mark int) bool {
	for _, c := range log[mark:] {
		if strings.HasPrefix(c, "detach ") {
			return true
		}
	}
	return false
}

// A volume that is still mounted, taken out of the spec and put back, stays attached.
// Detach has not started, and detaching would take the block device out from under the filesystem.
func TestAMountedVolumePutBackStaysAttached(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	device := s.Status.Volumes[0].Device
	if device == "" || s.Status.Volumes[0].AttachedTo != "w1" {
		t.Fatalf("not attached: %+v", s.Status.Volumes[0])
	}
	s.Status.Volumes[0].Mounted = true
	x.must(x.c.UpdateStatus(x.ctx, s))
	s = x.get("db")
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	x.reconcile("db")
	mid := x.get("db").Status.Volumes
	if len(mid) != 1 || !mid[0].Kept || !mid[0].Mounted || mid[0].AttachedTo != "w1" || mid[0].Device != device {
		t.Fatalf("dropped while mounted: %+v", mid)
	}
	if strings.HasPrefix(mid[0].Message, "detaching from ") {
		t.Fatalf("detach started while the volume is mounted: %+v", mid[0])
	}

	back := x.get("db")
	back.Spec.Volumes = []v1.Volume{blockVolume()}
	x.must(x.c.Update(x.ctx, back))
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Kept || got[0].AttachedTo != "w1" || got[0].Device != device || !got[0].Mounted {
		t.Fatalf("put back while mounted: %+v", got)
	}
	if detachesSince(x.fake.CallLog(), mark) {
		t.Fatalf("detached a mounted volume that was put back: %v", x.fake.CallLog()[mark:])
	}
}

// Kept, unmounted, and not yet detaching: putting the volume back keeps the device.
// A recorded "kept" is not a detach that has started.
func TestAKeptVolumePutBackBeforeDetachStaysAttached(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	device := s.Status.Volumes[0].Device
	s.Status.Volumes[0].Mounted = true
	x.must(x.c.UpdateStatus(x.ctx, s))
	s = x.get("db")
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	x.reconcile("db")
	mid := x.get("db")
	mid.Status.Volumes[0].Mounted = false
	x.must(x.c.UpdateStatus(x.ctx, mid))
	back := x.get("db")
	if !back.Status.Volumes[0].Kept || back.Status.Volumes[0].Mounted || back.Status.Volumes[0].Device != device ||
		strings.HasPrefix(back.Status.Volumes[0].Message, "detaching from ") {
		t.Fatalf("before it is put back: %+v", back.Status.Volumes[0])
	}
	back.Spec.Volumes = []v1.Volume{blockVolume()}
	x.must(x.c.Update(x.ctx, back))
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Kept || got[0].AttachedTo != "w1" || got[0].Device != device {
		t.Fatalf("put back before detach: %+v", got)
	}
	if detachesSince(x.fake.CallLog(), mark) {
		t.Fatalf("detached a volume whose detach had not started: %v", x.fake.CallLog()[mark:])
	}
}

// A detach that status already records is not finished while the volume is still mounted.
func TestAMountedVolumeIsNotDetachedWhileDetachIsRecorded(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	device := s.Status.Volumes[0].Device
	x.fake.DetachSlow = 2
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	x.reconcile("db")
	mid := x.get("db")
	if len(mid.Status.Volumes) != 1 || !strings.HasPrefix(mid.Status.Volumes[0].Message, "detaching from ") || mid.Status.Volumes[0].Device == "" {
		t.Fatalf("detach not in progress: %+v", mid.Status.Volumes)
	}
	mid.Status.Volumes[0].Mounted = true
	x.must(x.c.UpdateStatus(x.ctx, mid))
	back := x.get("db")
	back.Spec.Volumes = []v1.Volume{blockVolume()}
	x.must(x.c.Update(x.ctx, back))
	cur := x.get("db")
	if !cur.Status.Volumes[0].Mounted || !strings.HasPrefix(cur.Status.Volumes[0].Message, "detaching from ") {
		t.Fatalf("status before reconcile: %+v", cur.Status.Volumes[0])
	}
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Device != device || got[0].AttachedTo != "w1" {
		t.Fatalf("detached while mounted: %+v", got)
	}
	if detachesSince(x.fake.CallLog(), mark) {
		t.Fatalf("DetachVolume while mounted: %v", x.fake.CallLog()[mark:])
	}
}
