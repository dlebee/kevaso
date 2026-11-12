package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/store/storetest"
)

func TestSQLite(t *testing.T) {
	storetest.Run(t, func(t *testing.T, keep int) store.Store {
		s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "kevaso.db"), keep)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// Only SQLite outlives its process: objects, revisions and history survive a reopen.
func TestSQLiteSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kevaso.db")
	s, err := store.OpenSQLite(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	k := store.Key{Kind: "Silo", Namespace: "dev", Name: "a"}
	o, _ := s.Create(ctx, k, []byte(`1`))
	o2, _ := s.Update(ctx, k, []byte(`2`), o.Revision)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = store.OpenSQLite(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	got, err := s.Get(ctx, k)
	if err != nil || got.Revision != o2.Revision || string(got.Data) != `2` {
		t.Fatalf("after reopen: %+v, %v", got, err)
	}
	if rev, _ := s.Revision(ctx); rev != o2.Revision {
		t.Fatalf("revision after reopen %d, want %d", rev, o2.Revision)
	}
	// History survives too: a watcher can resume from before the restart.
	ch, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, o.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if ev := <-ch; ev.Type != store.Modified || ev.Object.Revision != o2.Revision {
		t.Fatalf("resumed event %s @%d, want MODIFIED @%d", ev.Type, ev.Object.Revision, o2.Revision)
	}
	// And the next write continues the same revision sequence.
	o3, _ := s.Update(ctx, k, []byte(`3`), o2.Revision)
	if o3.Revision != o2.Revision+1 {
		t.Fatalf("revision after reopen jumped to %d", o3.Revision)
	}
}

func TestSnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := store.OpenSQLite(filepath.Join(dir, "store.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Create(ctx, store.Key{Kind: "Silo", Namespace: "a", Name: "x"}, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snap.db")
	if err := s.Snapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	c, err := store.OpenSQLite(snap, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if o, err := c.Get(ctx, store.Key{Kind: "Silo", Namespace: "a", Name: "x"}); err != nil || string(o.Data) != `{"v":1}` {
		t.Fatalf("snapshot: %v %v", o, err)
	}
	if err := s.Snapshot(ctx, snap); err == nil {
		t.Error("overwrote an existing file")
	}
}
