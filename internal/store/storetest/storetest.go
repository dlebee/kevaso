// Package storetest is the conformance suite every store.Store implementation must pass: Memory,
// SQLite, and later etcd run exactly the same tests.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/store"
)

// Factory returns a new, empty store keeping at least `keep` events of watch history.
type Factory func(t *testing.T, keep int) store.Store

// Run runs the whole suite.
func Run(t *testing.T, newStore Factory) {
	tests := []struct {
		name string
		fn   func(*testing.T, Factory)
	}{
		{"CreateGet", testCreateGet},
		{"OptimisticConcurrency", testOptimisticConcurrency},
		{"Delete", testDelete},
		{"RevisionsAreGlobalAndIncreasing", testRevisions},
		{"ListSelectsSortsAndReportsRevision", testList},
		{"ReturnedDataIsACopy", testCopies},
		{"WatchFromListMissesNothing", testWatchFromList},
		{"WatchResumesFromAnyRevision", testWatchResume},
		{"WatchFiltersBySelector", testWatchFilter},
		{"WatchEndsWithContext", testWatchContext},
		{"WatchTooOldIsCompacted", testWatchCompacted},
		{"SlowWatcherIsDropped", testSlowWatcher},
		{"ConcurrentUpdatesNeverLoseWrites", testConcurrentUpdates},
		{"CloseEndsWatches", testClose},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore) })
	}
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func open(t *testing.T, f Factory, keep int) store.Store {
	s := f(t, keep)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func silo(ns, name string) store.Key { return store.Key{Kind: "Silo", Namespace: ns, Name: name} }

func mustCreate(t *testing.T, s store.Store, k store.Key, data string) store.Object {
	t.Helper()
	o, err := s.Create(ctxT(t), k, []byte(data))
	if err != nil {
		t.Fatalf("create %s: %v", k, err)
	}
	return o
}

func testCreateGet(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	o := mustCreate(t, s, silo("dev", "a"), `{"x":1}`)
	if o.Revision <= 0 || string(o.Data) != `{"x":1}` {
		t.Fatalf("created %+v", o)
	}
	got, err := s.Get(ctx, silo("dev", "a"))
	if err != nil || got.Revision != o.Revision || string(got.Data) != `{"x":1}` {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if _, err := s.Create(ctx, silo("dev", "a"), []byte(`{}`)); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: want ErrExists, got %v", err)
	}
	if _, err := s.Get(ctx, silo("dev", "missing")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get missing: want ErrNotFound, got %v", err)
	}
	if _, err := s.Create(ctx, store.Key{Kind: "Silo"}, nil); err == nil {
		t.Fatal("create without a name: want an error")
	}
	// Cluster-scoped and namespaced keys with the same name are different objects.
	mustCreate(t, s, store.Key{Kind: "Silo", Name: "a"}, `{"scope":"cluster"}`)
}

func testOptimisticConcurrency(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	k := silo("dev", "a")
	v1 := mustCreate(t, s, k, `1`)
	v2, err := s.Update(ctx, k, []byte(`2`), v1.Revision)
	if err != nil || v2.Revision <= v1.Revision || string(v2.Data) != `2` {
		t.Fatalf("update = %+v, %v", v2, err)
	}
	if _, err := s.Update(ctx, k, []byte(`stale`), v1.Revision); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: want ErrConflict, got %v", err)
	}
	if got, _ := s.Get(ctx, k); string(got.Data) != `2` {
		t.Fatalf("a refused update changed the object: %s", got.Data)
	}
	if _, err := s.Update(ctx, silo("dev", "missing"), []byte(`x`), 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: want ErrNotFound, got %v", err)
	}
}

func testDelete(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	k := silo("dev", "a")
	v1 := mustCreate(t, s, k, `1`)
	v2, _ := s.Update(ctx, k, []byte(`2`), v1.Revision)
	if _, err := s.Delete(ctx, k, v1.Revision); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale delete: want ErrConflict, got %v", err)
	}
	d, err := s.Delete(ctx, k, v2.Revision)
	if err != nil || d.Revision <= v2.Revision || string(d.Data) != `2` {
		t.Fatalf("delete = %+v, %v", d, err)
	}
	if _, err := s.Get(ctx, k); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete: want ErrNotFound, got %v", err)
	}
	if _, err := s.Delete(ctx, k, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: want ErrNotFound, got %v", err)
	}
	mustCreate(t, s, k, `again`)
	if _, err := s.Delete(ctx, k, 0); err != nil {
		t.Fatalf("unconditional delete: %v", err)
	}
}

func testRevisions(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	r0, err := s.Revision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := mustCreate(t, s, silo("dev", "a"), `a`)
	b := mustCreate(t, s, silo("prod", "b"), `b`)
	a2, _ := s.Update(ctx, a.Key, []byte(`a2`), a.Revision)
	if r0 >= a.Revision || a.Revision >= b.Revision || b.Revision >= a2.Revision {
		t.Fatalf("revisions not increasing across objects: %d %d %d %d", r0, a.Revision, b.Revision, a2.Revision)
	}
	if r, _ := s.Revision(ctx); r != a2.Revision {
		t.Fatalf("store revision %d, want the last write's %d", r, a2.Revision)
	}
}

func testList(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	mustCreate(t, s, silo("prod", "b"), `pb`)
	mustCreate(t, s, silo("dev", "z"), `dz`)
	mustCreate(t, s, silo("dev", "a"), `da`)
	mustCreate(t, s, store.Key{Kind: "Host", Name: "hv1"}, `h`)
	all, rev, err := s.List(ctx, store.Selector{Kind: "Silo"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range all {
		names = append(names, o.Namespace+"/"+o.Name)
	}
	if fmt.Sprint(names) != "[dev/a dev/z prod/b]" {
		t.Fatalf("list order = %v", names)
	}
	if cur, _ := s.Revision(ctx); rev != cur {
		t.Fatalf("list revision %d, store at %d", rev, cur)
	}
	dev, _, _ := s.List(ctx, store.Selector{Kind: "Silo", Namespace: "dev"})
	if len(dev) != 2 {
		t.Fatalf("namespace filter: got %d objects", len(dev))
	}
	none, _, _ := s.List(ctx, store.Selector{Kind: "Nope"})
	if len(none) != 0 {
		t.Fatalf("unknown kind: got %d objects", len(none))
	}
}

func testCopies(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	k := silo("dev", "a")
	in := []byte(`orig`)
	o, _ := s.Create(ctx, k, in)
	in[0] = 'X'
	o.Data[0] = 'Y'
	got, _ := s.Get(ctx, k)
	got.Data[0] = 'Z'
	again, _ := s.Get(ctx, k)
	if string(again.Data) != `orig` {
		t.Fatalf("stored data changed through a caller's slice: %s", again.Data)
	}
}

func next(t *testing.T, ch <-chan store.Event) store.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("watch closed early")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event within 5s")
	}
	return store.Event{}
}

func expectNone(t *testing.T, ch <-chan store.Event) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if ok {
			t.Fatalf("unexpected event %s %s", ev.Type, ev.Object.Key)
		}
	case <-time.After(100 * time.Millisecond):
	}
}

func testWatchFromList(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	a := mustCreate(t, s, silo("dev", "a"), `1`)
	_, rev, _ := s.List(ctx, store.Selector{Kind: "Silo"})
	ch, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, rev)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := s.Update(ctx, a.Key, []byte(`2`), a.Revision)
	b := mustCreate(t, s, silo("dev", "b"), `b`)
	d, _ := s.Delete(ctx, a.Key, 0)
	for _, want := range []struct {
		typ store.EventType
		key store.Key
		rev int64
	}{{store.Modified, a.Key, a2.Revision}, {store.Added, b.Key, b.Revision}, {store.Deleted, a.Key, d.Revision}} {
		ev := next(t, ch)
		if ev.Type != want.typ || ev.Object.Key != want.key || ev.Object.Revision != want.rev {
			t.Fatalf("event %s %s @%d, want %s %s @%d", ev.Type, ev.Object.Key, ev.Object.Revision, want.typ, want.key, want.rev)
		}
	}
	expectNone(t, ch)
}

func testWatchResume(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	var revs []int64
	for i := 0; i < 5; i++ {
		o := mustCreate(t, s, silo("dev", "s"+strconv.Itoa(i)), strconv.Itoa(i))
		revs = append(revs, o.Revision)
	}
	// Resuming from the 2nd write replays writes 3..5, in order, then goes live.
	ch, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, revs[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range revs[2:] {
		if ev := next(t, ch); ev.Object.Revision != want {
			t.Fatalf("replayed revision %d, want %d", ev.Object.Revision, want)
		}
	}
	live := mustCreate(t, s, silo("dev", "live"), `l`)
	if ev := next(t, ch); ev.Object.Revision != live.Revision {
		t.Fatalf("live revision %d, want %d", ev.Object.Revision, live.Revision)
	}
	// From 0: the whole history.
	all, _ := s.Watch(ctx, store.Selector{Kind: "Silo"}, 0)
	if ev := next(t, all); ev.Object.Revision != revs[0] {
		t.Fatalf("from 0 starts at %d, want %d", ev.Object.Revision, revs[0])
	}
}

func testWatchFilter(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	rev, _ := s.Revision(ctx)
	ch, _ := s.Watch(ctx, store.Selector{Kind: "Silo", Namespace: "dev"}, rev)
	mustCreate(t, s, silo("prod", "x"), `p`)
	mustCreate(t, s, store.Key{Kind: "Host", Name: "hv1"}, `h`)
	want := mustCreate(t, s, silo("dev", "y"), `d`)
	if ev := next(t, ch); ev.Object.Key != want.Key {
		t.Fatalf("got %s, want only dev silos", ev.Object.Key)
	}
	expectNone(t, ch)
}

func testWatchContext(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx, cancel := context.WithCancel(ctxT(t))
	ch, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		for ok {
			_, ok = <-ch
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch didn't close after its context ended")
	}
}

func testWatchCompacted(t *testing.T, f Factory) {
	s := open(t, f, 3)
	ctx := ctxT(t)
	first := mustCreate(t, s, silo("dev", "first"), `f`)
	for i := 0; i < 20; i++ {
		mustCreate(t, s, silo("dev", "n"+strconv.Itoa(i)), `n`)
	}
	if _, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, first.Revision-1); !errors.Is(err, store.ErrCompacted) {
		t.Fatalf("watch from compacted history: want ErrCompacted, got %v", err)
	}
	// From the current revision is always fine.
	cur, _ := s.Revision(ctx)
	if _, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, cur); err != nil {
		t.Fatalf("watch from now: %v", err)
	}
}

func testSlowWatcher(t *testing.T, f Factory) {
	s := open(t, f, 5000)
	ctx := ctxT(t)
	rev, _ := s.Revision(ctx)
	ch, _ := s.Watch(ctx, store.Selector{Kind: "Silo"}, rev)
	for i := 0; i < 3000; i++ { // never read: the watcher falls behind
		mustCreate(t, s, silo("dev", "s"+strconv.Itoa(i)), `x`)
	}
	n := 0
	for range ch { // drains what was buffered, then the channel must be closed
		n++
	}
	if n >= 3000 {
		t.Fatalf("a watcher that never read got all %d events: it should have been dropped", n)
	}
}

func testConcurrentUpdates(t *testing.T, f Factory) {
	s := open(t, f, 0)
	ctx := ctxT(t)
	k := silo("dev", "counter")
	mustCreate(t, s, k, `0`)
	const workers, each = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				for { // read, modify, write; retry on conflict
					o, err := s.Get(ctx, k)
					if err != nil {
						t.Error(err)
						return
					}
					n, _ := strconv.Atoi(string(o.Data))
					if _, err := s.Update(ctx, k, []byte(strconv.Itoa(n+1)), o.Revision); err == nil {
						break
					} else if !errors.Is(err, store.ErrConflict) {
						t.Error(err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	o, _ := s.Get(ctx, k)
	if string(o.Data) != strconv.Itoa(workers*each) {
		t.Fatalf("counter = %s, want %d: a write was lost", o.Data, workers*each)
	}
}

func testClose(t *testing.T, f Factory) {
	s := f(t, 0)
	ctx := ctxT(t)
	ch, _ := s.Watch(ctx, store.Selector{Kind: "Silo"}, 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("event after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch didn't close with the store")
	}
	if _, err := s.Get(ctx, silo("dev", "a")); err == nil {
		t.Fatal("get on a closed store: want an error")
	}
}
