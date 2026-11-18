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
	if _, err := s.revokeHost(ctx, "hv1"); err != nil {
		t.Fatal(err)
	}
	err = s.removedHostCert(ctx, "hv1", old)
	if !errors.Is(err, errRemovalUnreadable) || errors.Is(err, errHostRemoved) {
		t.Fatalf("a pending removal with its Host still there: want try again, got %v", err)
	}
	// The Host is gone (its delete committed elsewhere): the same pending record is final.
	o, _ := mem.Get(ctx, hostKey)
	if _, err := mem.Delete(ctx, hostKey, o.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errHostRemoved) {
		t.Fatalf("a pending removal whose Host is gone: want final, got %v", err)
	}
	// Finalized: final even with a Host of that name there again.
	s.finalizeHostRemoval(ctx, "hv1")
	if _, err := mem.Create(ctx, hostKey, []byte(`{"apiVersion":"kevaso/v1","kind":"Host","metadata":{"name":"hv1"}}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errHostRemoved) {
		t.Fatalf("a finalized removal: want final, got %v", err)
	}
	// A record with no removal time is unreadable, never final.
	o, _ = mem.Get(ctx, hostRemovalKey("hv1"))
	if _, err := mem.Update(ctx, hostRemovalKey("hv1"), []byte(`{}`), o.Revision); err != nil {
		t.Fatal(err)
	}
	if err := s.removedHostCert(ctx, "hv1", old); !errors.Is(err, errRemovalUnreadable) {
		t.Fatalf("a record with no removal time: want try again, got %v", err)
	}
}
