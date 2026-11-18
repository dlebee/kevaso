package apiserver

import (
	"context"
	"errors"
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
	if snapA.wrote, err = s.revokeHost(ctx, "hv1", "", hostRemovalSnap{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.revokeHost(ctx, "hv1", "", hostRemovalSnap{}); err != nil { // the second delete's record
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
	if snapC.wrote, err = s.revokeHost(ctx, "hv1", "", hostRemovalSnap{}); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreHostRemoval(ctx, "hv1", snapC); err != nil {
		t.Fatal(err)
	}
	// What stood before was a pending record (a delete that never finished), which counts as
	// none: putting back "none" removes the record.
	if snapC.ok {
		t.Fatal("a pending record was taken for what stood before")
	}
	if _, err := mem.Get(ctx, hostRemovalKey("hv1")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("undoing its own record should leave what stood before it (none): %v", err)
	}
}
