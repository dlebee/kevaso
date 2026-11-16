package agent

import (
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A person's confirmation removes a kept copy. It does not remove one the store places here:
// that copy is this host's, and the confirmation is not a delete of it.
func TestAConfirmedRemovalDoesNotRemoveWhileTheStorePlacesTheCopyHere(t *testing.T) {
	g := newGuardRig(t, nil, nil)
	s := g.create(guardSilo("single", nil), "hv1", "")
	id := idOf(s)
	if err := g.rt.Create(g.ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	g.a.removeConfirmed.Store(id.UID, id)
	remove, why, err := g.a.mayRemove(g.ctx, id)
	if remove || err != nil {
		t.Fatalf("the store places it here: remove=%v (%q, %v)", remove, why, err)
	}
}
