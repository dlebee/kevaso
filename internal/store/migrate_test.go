package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

var kinds = []string{"Host", "Secret", "Silo"}

// fillSQLite writes objects of several kinds and namespaces, with updates and deletes, so that
// revision order isn't key order, and returns the store's revision and what each key holds.
func fillSQLite(t *testing.T, s *store.SQLite) (int64, map[store.Key]string) {
	t.Helper()
	ctx := context.Background()
	want := map[store.Key]string{}
	for i := 349; i >= 0; i-- { // more than three batches, written in reverse key order
		k := store.Key{Kind: kinds[i%3], Namespace: []string{"", "dev", "prod"}[i%3], Name: fmt.Sprintf("o%03d", i)}
		o, err := s.Create(ctx, k, []byte(`{"n":`+strconv.Itoa(i)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		want[k] = string(o.Data)
		switch i % 7 {
		case 0:
			if _, err := s.Update(ctx, k, []byte(`{"updated":true}`), o.Revision); err != nil {
				t.Fatal(err)
			}
			want[k] = `{"updated":true}`
		case 1:
			if _, err := s.Delete(ctx, k, 0); err != nil {
				t.Fatal(err)
			}
			delete(want, k)
		}
	}
	rev, _ := s.Revision(ctx)
	return rev, want
}

func listAll(t *testing.T, s store.Store) map[store.Key]store.Object {
	t.Helper()
	got := map[store.Key]store.Object{}
	for _, kind := range kinds {
		objs, _, err := s.List(context.Background(), store.Selector{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range objs {
			got[o.Key] = o
		}
	}
	return got
}

func TestMigrateSQLite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	src, err := store.OpenSQLite(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A watcher from before the migration: it saw everything up to some revision.
	seen, _ := src.Revision(ctx)
	old, err := src.Watch(ctx, store.Selector{Kind: "Silo"}, seen)
	if err != nil {
		t.Fatal(err)
	}
	sqliteRev, want := fillSQLite(t, src)
	_ = src.Close()
	for range old { // the old store's watches end with it
	}

	cli := newEtcd(t)
	t0 := time.Now()
	e, res, err := store.MigrateSQLite(ctx, cli, path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("migrated %d objects in %v", res.Objects, time.Since(t0))
	if !res.Ran || res.Objects != len(want) || res.From != sqliteRev || e.Base() != sqliteRev {
		t.Fatalf("migration %+v, base %d; want %d objects from revision %d", res, e.Base(), len(want), sqliteRev)
	}
	got := listAll(t, e)
	if len(got) != len(want) {
		t.Fatalf("%d objects in etcd, %d in SQLite", len(got), len(want))
	}
	for k, data := range want {
		o, ok := got[k]
		if !ok || string(o.Data) != data {
			t.Fatalf("%s: etcd has %q (present %v), SQLite had %q", k, o.Data, ok, data)
		}
		if o.Revision <= sqliteRev {
			t.Fatalf("%s: revision %d, not above the SQLite store's %d", k, o.Revision, sqliteRev)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the SQLite store is still at %s: %v", path, err)
	}
	if _, err := os.Stat(path + store.MigratedSuffix); err != nil {
		t.Fatalf("the SQLite store wasn't kept as a copy: %v", err)
	}

	// The old watcher resumes: from its revision, or the SQLite store's last, it's told to re-list.
	for _, from := range []int64{seen, sqliteRev, 0} {
		if _, err := e.Watch(ctx, store.Selector{Kind: "Silo"}, from); !errors.Is(err, store.ErrCompacted) {
			t.Fatalf("watch from %d after the migration: want ErrCompacted, got %v", from, err)
		}
	}
	// It re-lists, and watches from the list's revision: it gets what happens next.
	objs, rev, err := e.List(ctx, store.Selector{Kind: "Silo"})
	if err != nil || rev <= sqliteRev || len(objs) == 0 {
		t.Fatalf("re-list: %d objects at %d, %v", len(objs), rev, err)
	}
	ch, err := e.Watch(ctx, store.Selector{Kind: "Silo"}, rev)
	if err != nil {
		t.Fatal(err)
	}
	u, err := e.Update(ctx, objs[0].Key, []byte(`{"after":true}`), objs[0].Revision)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ch:
		if ev.Type != store.Modified || ev.Object.Revision != u.Revision {
			t.Fatalf("event %s @%d, want MODIFIED @%d", ev.Type, ev.Object.Revision, u.Revision)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event after the re-list")
	}
	_ = e.Close()

	// Never twice: again with the file gone, and again with it back (a crash before the rename).
	e2, res2, err := store.MigrateSQLite(ctx, cli, path, 0)
	if err != nil || res2.Ran {
		t.Fatalf("second run: %+v, %v", res2, err)
	}
	_ = e2.Close()
	if err := os.Rename(path+store.MigratedSuffix, path); err != nil {
		t.Fatal(err)
	}
	e3, res3, err := store.MigrateSQLite(ctx, cli, path, 0)
	if err != nil || res3.Ran {
		t.Fatalf("run with the file back: %+v, %v", res3, err)
	}
	defer func() { _ = e3.Close() }()
	if o, _ := e3.Get(ctx, u.Key); o.Revision != u.Revision {
		t.Fatalf("the object was rewritten: revision %d, want %d", o.Revision, u.Revision)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the returned SQLite file wasn't retired")
	}
}

// An etcd store that started empty is not overwritten by a SQLite file that turns up later.
func TestMigrateRefusesTwoStores(t *testing.T) {
	ctx := context.Background()
	cli := newEtcd(t)
	e := openEtcd(t, cli, 0)
	_ = e.Close()
	path := filepath.Join(t.TempDir(), "store.db")
	s, _ := store.OpenSQLite(path, 0)
	_, _ = s.Create(ctx, store.Key{Kind: "Silo", Namespace: "dev", Name: "a"}, []byte(`{}`))
	_ = s.Close()
	if _, _, err := store.MigrateSQLite(ctx, cli, path, 0); err == nil {
		t.Fatal("migrated into an etcd store that already had its own history")
	}
}

// swap is an http.Handler whose target changes: one API address across a control-plane restart.
type swap struct{ h atomic.Pointer[http.Handler] }

func (s *swap) set(h http.Handler)                                { s.h.Store(&h) }
func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) { (*s.h.Load()).ServeHTTP(w, r) }

// A real informer watching a control plane on SQLite, which restarts on etcd after the migration:
// the informer re-lists by itself, its cache holds every object with its new resource version,
// and it sees writes made after the switch.
func TestInformerRecoversAfterMigration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "store.db")
	sq, err := store.OpenSQLite(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	srv1, err := apiserver.New(sq, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	var h swap
	h.set(srv1)
	ts := httptest.NewServer(&h)
	defer ts.Close()
	c := client.New(ts.URL)
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	silo := func(name string) *v1.Silo {
		return &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", Image: "ubuntu-24.04", Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	}
	for _, n := range []string{"a", "b"} {
		if err := c.Create(ctx, silo(n)); err != nil {
			t.Fatal(err)
		}
	}
	inf := informer.New(c, "Silo")
	go inf.Run(ctx)
	if !inf.WaitSynced(ctx) {
		t.Fatal("not synced")
	}
	before, _ := inf.Get("dev", "a")
	oldRV, _ := strconv.ParseInt(before.GetObjectMeta().ResourceVersion, 10, 64)

	// The restart: the SQLite control plane stops, the etcd one starts on the migrated data.
	_ = sq.Close()
	e, _, err := store.MigrateSQLite(ctx, newEtcd(t), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = e.Close() }()
	srv2, err := apiserver.New(e, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	h.set(srv2)
	if err := c.Create(ctx, silo("c")); err != nil {
		t.Fatal(err)
	}
	for {
		a, okA := inf.Get("dev", "a")
		_, okC := inf.Get("dev", "c")
		if okA && okC {
			rv, _ := strconv.ParseInt(a.GetObjectMeta().ResourceVersion, 10, 64)
			if rv > oldRV && len(inf.List()) == 3 {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the informer didn't recover: %d objects cached", len(inf.List()))
		case <-time.After(50 * time.Millisecond):
		}
	}
}
