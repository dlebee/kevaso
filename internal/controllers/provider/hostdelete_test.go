package provider_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/engine"
)

// Deleting a host detaches a volume that moved off it. It does not delete the volume.
func TestHostDeleteDoesNotDeleteAVolume(t *testing.T) {
	x := newK037(t)
	s := x.silo("data", "w2")
	handle := s.Status.Volumes[0].Handle
	if handle == "" || s.Status.Volumes[0].AttachedTo != "w2" {
		t.Fatalf("not attached: %+v", s.Status.Volumes)
	}
	s.Status.Host = "w1"
	s.Status.Volumes[0].Mounted = true
	x.must(x.c.UpdateStatus(x.ctx, s))
	if err := x.c.Delete(x.ctx, "Host", "", "w2", client.Precondition{ConfirmOff: true}); err != nil {
		t.Fatal(err)
	}
	before := len(x.fake.CallLog())
	if _, err := x.volumes().Reconcile(x.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "data"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range x.fake.CallLog()[before:] {
		if strings.HasPrefix(call, "delete-volume") {
			t.Fatalf("a volume delete was issued: %s", call)
		}
	}
	_, volumes, _ := x.fake.Snapshot()
	if _, ok := volumes[handle]; !ok {
		t.Fatal("the volume's data is gone")
	}
	got := x.get("data")
	if len(got.Status.Volumes) != 1 || got.Status.Volumes[0].Handle != handle || got.Status.Volumes[0].AttachedTo == "w2" {
		t.Fatalf("still on the deleted host, or dropped: %+v", got.Status.Volumes)
	}
}
