package apiserver

import (
	"context"
	"testing"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// A refused host delete undoes only the removal record it wrote. Here a second delete recorded
// the host's removal after the first one did, and its Host is not deleted yet: the first one's
// undo must leave the second one's record in place.
func TestARefusedHostDeleteUndoesOnlyItsOwnRecord(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory(0)
	s, err := New(mem, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Create(ctx, store.Key{Kind: "Host", Name: "hv1"}, []byte(`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"hv1"}}`)); err != nil {
		t.Fatal(err)
	}
	snapA, err := s.hostRemovalSnap(ctx, "hv1")
	if err != nil {
		t.Fatal(err)
	}
	if snapA.wrote, err = s.revokeHost(ctx, "hv1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.revokeHost(ctx, "hv1"); err != nil { // the second delete's record
		t.Fatal(err)
	}
	if err := s.restoreHostRemoval(ctx, "hv1", snapA); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.hostRemoval(ctx, "hv1"); !ok {
		t.Fatal("the first delete's undo removed the second delete's removal record")
	}
	// Its own record, with nothing written since, is undone.
	snapC, err := s.hostRemovalSnap(ctx, "hv1")
	if err != nil {
		t.Fatal(err)
	}
	if snapC.wrote, err = s.revokeHost(ctx, "hv1"); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreHostRemoval(ctx, "hv1", snapC); err != nil {
		t.Fatal(err)
	}
	o, err := mem.Get(ctx, hostRemovalKey("hv1"))
	if err != nil || string(o.Data) != string(snapC.data) {
		t.Fatalf("undoing its own record should put back the one before it: %v", err)
	}
}
