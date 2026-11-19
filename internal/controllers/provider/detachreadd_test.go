package provider_test

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A volume put back while its detach is still in progress is detached to the end, then
// attached. The device named during the detach is not treated as attached.
func TestAVolumePutBackDuringDetachIsAttachedAgain(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	handle := s.Status.Volumes[0].Handle
	if s.Status.Volumes[0].Device == "" || s.Status.Volumes[0].AttachedTo != "w1" {
		t.Fatalf("not attached: %+v", s.Status.Volumes[0])
	}
	x.fake.DetachSlow = 2
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	x.reconcile("db")
	mid := x.get("db").Status.Volumes
	if len(mid) != 1 || !mid[0].Kept || mid[0].AttachedTo != "w1" || mid[0].Device == "" || !strings.HasPrefix(mid[0].Message, "detaching from ") {
		t.Fatalf("detach not in progress: %+v", mid)
	}

	back := x.get("db")
	back.Spec.Volumes = []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}
	x.must(x.c.Update(x.ctx, back))
	mark := len(x.fake.CallLog())
	x.reconcile("db")
	again := x.get("db").Status.Volumes
	if len(again) != 1 || again[0].Device != "" || !strings.HasPrefix(again[0].Message, "detaching from ") {
		t.Fatalf("device trusted while detach is in progress: %+v", again)
	}
	x.reconcile("db")
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Kept || got[0].Handle != handle || got[0].AttachedTo != "w1" || got[0].Device == "" {
		t.Fatalf("not attached again: %+v", got)
	}
	var detaches, attachAt int
	for i, c := range x.fake.CallLog()[mark:] {
		if strings.HasPrefix(c, "detach ") {
			detaches++
		}
		if strings.HasPrefix(c, "attach ") {
			attachAt = i
		}
	}
	if detaches < 2 || attachAt == 0 {
		t.Fatalf("detach then attach, got %v", x.fake.CallLog()[mark:])
	}
}
