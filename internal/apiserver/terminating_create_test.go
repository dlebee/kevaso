package apiserver

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// A namespace being deleted takes no new lease, approval, pane or bundle. One that is already
// there can still be updated, so a sweep can finish.
func TestNothingNewIsMadeInANamespaceBeingDeleted(t *testing.T) {
	ctx := context.Background()
	s, err := New(store.NewMemory(0), clock.NewFake(time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	now := s.clock.Now()
	silo := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web", UID: "uid-web"}}
	held := &v1.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web.held"}}
	if err := s.putLease(ctx, held, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.markNamespace(ctx, "dev", "Terminating", "", ""); err != nil {
		t.Fatal(err)
	}
	existing, rev, err := s.getLease(ctx, "dev", "web.held")
	if err != nil {
		t.Fatal(err)
	}
	existing.Status.Phase = v1.LeaseOpen
	if err := s.putLease(ctx, existing, rev, existing); err != nil {
		t.Fatalf("updating a lease already there: %v", err)
	}

	refused := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "being deleted") {
			t.Fatalf("%s: %v", what, err)
		}
	}
	absent := func(kind, name string) {
		t.Helper()
		_, err := s.store.Get(ctx, store.Key{Kind: kind, Namespace: "dev", Name: name})
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s/%s stored while the namespace is being deleted: %v", kind, name, err)
		}
	}

	refused("lease", s.putLease(ctx, &v1.Lease{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web.extra"}}, 0, nil))
	absent("Lease", "web.extra")
	refused("approval", s.putApproval(ctx, &v1.Approval{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "ask"}}, 0, nil))
	absent("Approval", "ask")
	refused("pane", s.putPane(ctx, silo, v1.PaneReport{Pane: "main", Kind: "status"}, now))
	absent("Pane", "web.main")
	refused("bundle", s.putBundle(ctx, silo, "abc", []byte("hi"), now))
	absent(bundleKind, bundleName("web", "abc"))
}
