package moves

import (
	"errors"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A plain move (no --recreate) of a container silo is refused as a microVM's is when its root
// can't travel (audit checkpoint 4, deletes and data): a container's own files are never kept, so
// a plain move started it fresh elsewhere, init steps not run again, while a microVM was refused.
// Both now need onHostLoss: Recreate and --recreate, and the refusal says so in the same words.
func TestAPlainMoveOfAContainerIsRefusedLikeAMicroVMs(t *testing.T) {
	vm := silo("cloud-hypervisor", "")
	_, vmErr := PlanMove(vm, Of(vm, classes), Request{To: "hv3"}, false, false, "")
	if !errors.Is(vmErr, ErrNotMovable) {
		t.Fatalf("a microVM on a local disk: %v, want ErrNotMovable", vmErr)
	}
	for _, rt := range []string{"docker", "podman", "openshell-container"} {
		for _, vols := range [][]v1.Volume{nil, {{Name: "data", Class: "juicefs"}}} {
			c := silo(rt, "", vols...)
			_, err := PlanMove(c, Of(c, classes), Request{To: "hv3"}, false, false, "")
			if !errors.Is(err, ErrNotMovable) {
				t.Fatalf("a plain move of a %s silo (volumes %v): %v, want ErrNotMovable", rt, vols, err)
			}
			if want := "a fresh copy needs onHostLoss: Recreate and --recreate"; !strings.Contains(err.Error(), want) || !strings.Contains(vmErr.Error(), want) {
				t.Errorf("%s: %q and the microVM's %q don't both say %q", rt, err, vmErr, want)
			}
			// Lost and confirmed fenced too: a plain move still starts it fresh.
			if _, err := PlanMove(c, Of(c, classes), Request{To: "hv3", ConfirmFenced: true}, true, false, ""); !errors.Is(err, ErrNotMovable) {
				t.Errorf("%s from a lost host, confirmed: %v, want ErrNotMovable", rt, err)
			}
			// With onHostLoss: Recreate and --recreate it goes, as a fresh copy.
			r := silo(rt, v1.OnHostLossRecreate, vols...)
			if p, err := PlanMove(r, Of(r, classes), Request{To: "hv3", Recreate: true}, false, false, ""); err != nil || p.WithData {
				t.Errorf("%s --recreate: %+v, %v, want a fresh copy", rt, p, err)
			}
		}
	}
	// Ending a handoff whose source is lost is not a new move: its destination keeps it as planned.
	h := silo("docker", "")
	h.Status.Host, h.Status.MovingFrom = "hv3", "hv1"
	if p, err := PlanMove(h, Of(h, classes), Request{To: "hv3", ConfirmFenced: true}, false, true, ""); err != nil || p.From != "hv1" {
		t.Errorf("ending a container's handoff from a lost source: %+v, %v", p, err)
	}
}
