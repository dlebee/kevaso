package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"kevaso.com/core/internal/store"
)

// The store's revision is what workers judge a control plane's recency by (brainstorm §0.7): it
// must only grow within one store's history, through compaction, a second store on the same etcd
// (another system node, a new leader) and a reopen (a restart or an upgrade).
func TestTheRevisionOnlyGrows(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, stores ...store.Store) {
		t.Helper()
		var last int64
		for i := range 60 {
			st := stores[i%len(stores)]
			o, err := st.Create(ctx, store.Key{Kind: "Namespace", Name: fmt.Sprintf("n%d", i)}, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if o.Revision <= last {
				t.Fatalf("write %d at revision %d, after %d", i, o.Revision, last)
			}
			last = o.Revision
			for _, s := range stores {
				rev, err := s.Revision(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if rev < last {
					t.Fatalf("write %d at %d, a store answers %d", i, last, rev)
				}
			}
		}
	}
	t.Run("etcd, compacted, two stores", func(t *testing.T) {
		cli := newEtcd(t)
		a, b := openEtcd(t, cli, 10), openEtcd(t, cli, 10) // keep 10: compacts all along
		check(t, a, b)
		before, _ := a.Revision(ctx)
		_ = a.Close()
		c := openEtcd(t, cli, 10)
		if rev, _ := c.Revision(ctx); rev < before {
			t.Fatalf("reopened at %d, was %d", rev, before)
		}
	})
	t.Run("sqlite, reopened", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "store.db")
		s, err := store.OpenSQLite(path, 10)
		if err != nil {
			t.Fatal(err)
		}
		check(t, s)
		before, _ := s.Revision(ctx)
		_ = s.Close()
		s2, err := store.OpenSQLite(path, 10)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s2.Close() }()
		if rev, _ := s2.Revision(ctx); rev != before {
			t.Fatalf("reopened at %d, was %d", rev, before)
		}
	})
}
