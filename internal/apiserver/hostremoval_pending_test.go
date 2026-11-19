package apiserver

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// A removal is final only once its Host delete commits. Until then (a delete that may still be
// refused) a host's old certificate is refused for now, never with the final answer.
func TestARemovalIsFinalOnlyOnceTheDeleteCommits(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory(0)
	s, err := New(mem, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	hostKey := store.Key{Kind: "Host", Name: "hv1"}
	if _, err := mem.Create(ctx, hostKey, []byte(`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"hv1"}}`)); err != nil {
		t.Fatal(err)
	}
	old := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Now().Add(-time.Hour)}
	if _, err := s.revokeHost(ctx, "hv1", "", hostRemovalSnap{}); err != nil {
		t.Fatal(err)
	}
	_, err = s.removedHostCert(ctx, "hv1", old)
	if !errors.Is(err, errRemovalUnreadable) || errors.Is(err, errHostRemoved) {
		t.Fatalf("a pending removal with its Host still there: want try again, got %v", err)
	}
	// The Host is gone (its delete committed elsewhere): the same pending record is final.
	o, _ := mem.Get(ctx, hostKey)
	if _, err := mem.Delete(ctx, hostKey, o.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errHostRemoved) {
		t.Fatalf("a pending removal whose Host is gone: want final, got %v", err)
	}
	// Finalized: final even with a Host of that name there again.
	s.finalizeHostRemoval(ctx, "hv1")
	if _, err := mem.Create(ctx, hostKey, []byte(`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"hv1"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errHostRemoved) {
		t.Fatalf("a finalized removal: want final, got %v", err)
	}
	// A record with no removal time is unreadable, never final.
	o, _ = mem.Get(ctx, hostRemovalKey("hv1"))
	if _, err := mem.Update(ctx, hostRemovalKey("hv1"), []byte(`{}`), o.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errRemovalUnreadable) {
		t.Fatalf("a record with no removal time: want try again, got %v", err)
	}
}

// A pending removal a member left behind is settled: final when the delete committed (the Host
// gone, or made again with another UID), and put back when the Host stood unchanged.
func TestAPendingRemovalLeftBehindIsSettled(t *testing.T) {
	ctx := context.Background()
	fc := clock.NewFake(time.Now())
	mem := store.NewMemory(0)
	s, err := New(mem, fc)
	if err != nil {
		t.Fatal(err)
	}
	hostKey := store.Key{Kind: "Host", Name: "hv1"}
	mkHost := func(uid string) {
		t.Helper()
		if _, err := mem.Create(ctx, hostKey, []byte(`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"hv1","uid":"`+uid+`"}}`)); err != nil {
			t.Fatal(err)
		}
	}
	dropHost := func() {
		t.Helper()
		o, _ := mem.Get(ctx, hostKey)
		if _, err := mem.Delete(ctx, hostKey, o.Revision); err != nil {
			t.Fatal(err)
		}
	}
	old := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: fc.Now().Add(-time.Hour)}

	// The delete committed and its finalize was lost; the name was then added again.
	mkHost("uid-1")
	if _, err := s.revokeHost(ctx, "hv1", "uid-1", hostRemovalSnap{}); err != nil {
		t.Fatal(err)
	}
	dropHost()
	mkHost("uid-2")
	if _, err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errHostRemoved) {
		t.Fatalf("a Host made again after the delete: want the old certificate's final refusal, got %v", err)
	}
	s.sweepHostRemovalsOnce(ctx)
	if rec, ok := s.hostRemoval(ctx, "hv1"); !ok || rec.Pending {
		t.Fatalf("the sweep left the committed removal pending: %+v %v", rec, ok)
	}

	// A delete that never committed: the Host stands unchanged. Within pendingStale it stays
	// pending; after it, what stood before comes back (here, none).
	dropHost()
	mkHost("uid-3")
	o, _ := mem.Get(ctx, hostRemovalKey("hv1"))
	_, _ = mem.Delete(ctx, hostRemovalKey("hv1"), o.Revision)
	if _, err := s.revokeHost(ctx, "hv1", "uid-3", hostRemovalSnap{}); err != nil {
		t.Fatal(err)
	}
	s.sweepHostRemovalsOnce(ctx)
	if rec, ok := s.hostRemoval(ctx, "hv1"); !ok || !rec.Pending {
		t.Fatalf("a fresh pending removal was settled early: %+v %v", rec, ok)
	}
	fc.Step(pendingStale + time.Second)
	s.sweepHostRemovalsOnce(ctx)
	if _, err := mem.Get(ctx, hostRemovalKey("hv1")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stale pending removal with its Host unchanged was not put back: %v", err)
	}
	if _, err := s.removedHostCert(ctx, "hv1", old); err != nil {
		t.Fatalf("after a delete that never committed, the host's certificate: %v", err)
	}
}
