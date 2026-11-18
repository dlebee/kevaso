package provider_test

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A volume taken out of the spec is detached and kept. The same name and class attaches that
// handle again. The volume is deleted when the silo is deleted.
func TestAVolumeTakenOutOfTheSpecIsKept(t *testing.T) {
	x := newK037(t)
	s := x.silo("db", "w1")
	vol := s.Status.Volumes[0]
	if vol.Handle == "" || vol.AttachedTo != "w1" {
		t.Fatalf("not attached: %+v", vol)
	}
	mark := len(x.fake.CallLog())
	s.Spec.Volumes = nil
	x.must(x.c.Update(x.ctx, s))
	for range 3 {
		x.reconcile("db")
	}
	for _, c := range x.callsOn(mark, vol.Handle) {
		if strings.HasPrefix(c, "delete-volume ") {
			t.Fatalf("deleted while the silo lives: %v", x.callsOn(mark, vol.Handle))
		}
	}
	if _, vols, _ := x.fake.Snapshot(); vols[vol.Handle].Handle == "" {
		t.Fatal("the volume is gone from the plugin")
	}
	got := x.get("db").Status.Volumes
	if len(got) != 1 || got[0].Handle != vol.Handle || !got[0].Kept || got[0].AttachedTo != "" {
		t.Fatalf("kept status: %+v", got)
	}
	if len(x.callsOn(mark, vol.Handle)) == 0 || !strings.HasPrefix(x.callsOn(mark, vol.Handle)[0], "detach ") {
		t.Fatalf("not detached: %v", x.callsOn(mark, vol.Handle))
	}

	back := x.get("db")
	back.Spec.Volumes = []v1.Volume{{Name: "data", Class: kplugintest.ClassBlock, Size: "1Gi", MountPath: "/data"}}
	x.must(x.c.Update(x.ctx, back))
	mark = len(x.fake.CallLog())
	for range 3 {
		x.reconcile("db")
	}
	again := x.get("db").Status.Volumes
	if len(again) != 1 || again[0].Handle != vol.Handle || again[0].Kept || again[0].AttachedTo != "w1" {
		t.Fatalf("reattached: %+v", again)
	}
	for _, c := range x.fake.CallLog()[mark:] {
		if strings.HasPrefix(c, "ensure-volume ") || strings.HasPrefix(c, "delete-volume ") {
			t.Fatalf("a new volume was made: %v", x.fake.CallLog()[mark:])
		}
	}

	x.must(x.c.Delete(x.ctx, "Silo", "d", "db"))
	mark = len(x.fake.CallLog())
	for range 4 {
		if _, err := x.volumes().Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "db"}); err != nil {
			t.Fatal(err)
		}
	}
	deleted := false
	for _, c := range x.callsOn(mark, vol.Handle) {
		if strings.HasPrefix(c, "delete-volume ") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("deleting the silo did not delete the volume: %v", x.callsOn(mark, vol.Handle))
	}
}
