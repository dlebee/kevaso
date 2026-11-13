package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/internal/store"
)

// Compare-and-swap under contention, for every store (run with -race): the races a control plane's
// writers make every day, beyond read-modify-write (storetest's): creates of one key, updates
// racing deletes, deletes conditional on a revision, and a watch that must see every revision in
// order while it all happens.

func stores(t *testing.T) map[string]func(t *testing.T) store.Store {
	out := map[string]func(t *testing.T) store.Store{
		"memory": func(*testing.T) store.Store { return store.NewMemory(0) },
		"sqlite": func(t *testing.T) store.Store {
			s, err := store.OpenSQLite(filepath.Join(t.TempDir(), "kevaso.db"), 0)
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
	if !testing.Short() {
		out["etcd"] = func(t *testing.T) store.Store { return openEtcd(t, newEtcd(t), 0) }
	}
	return out
}

func TestStressCreateOneKey(t *testing.T) {
	for name, open := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()
			for round := range 20 {
				k := store.Key{Kind: "Silo", Namespace: "dev", Name: fmt.Sprintf("s%d", round)}
				var won atomic.Int32
				var wg sync.WaitGroup
				for w := range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, err := s.Create(ctx, k, []byte(strconv.Itoa(w)))
						switch {
						case err == nil:
							won.Add(1)
						case !errors.Is(err, store.ErrExists):
							t.Error(err)
						}
					}()
				}
				wg.Wait()
				if won.Load() != 1 {
					t.Fatalf("%s: %d creates won", k, won.Load())
				}
			}
		})
	}
}

// Updates and a conditional delete race on one object: either the delete wins (then every later
// update is NotFound, and the deleted state is the last one written), or it loses with Conflict;
// never an update that lands after the delete, never a delete of a state it didn't see.
func TestStressUpdateRacesDelete(t *testing.T) {
	for name, open := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx := context.Background()
			for round := range 20 {
				k := store.Key{Kind: "Silo", Namespace: "dev", Name: fmt.Sprintf("d%d", round)}
				o, err := s.Create(ctx, k, []byte("0"))
				if err != nil {
					t.Fatal(err)
				}
				var mu sync.Mutex
				last := o
				var wg sync.WaitGroup
				for range 4 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for range 10 {
							cur, err := s.Get(ctx, k)
							if errors.Is(err, store.ErrNotFound) {
								return
							}
							if err != nil {
								t.Error(err)
								return
							}
							n, _ := strconv.Atoi(string(cur.Data))
							got, err := s.Update(ctx, k, []byte(strconv.Itoa(n+1)), cur.Revision)
							switch {
							case err == nil:
								mu.Lock()
								if got.Revision > last.Revision {
									last = got
								}
								mu.Unlock()
							case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrNotFound):
							default:
								t.Error(err)
							}
						}
					}()
				}
				var deleted store.Object
				var delErr error
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						cur, err := s.Get(ctx, k)
						if err != nil {
							delErr = err
							return
						}
						deleted, delErr = s.Delete(ctx, k, cur.Revision)
						if !errors.Is(delErr, store.ErrConflict) {
							return
						}
					}
				}()
				wg.Wait()
				if delErr != nil {
					t.Fatalf("delete: %v", delErr)
				}
				if _, err := s.Get(ctx, k); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("after the delete: %v", err)
				}
				if _, err := s.Update(ctx, k, []byte("x"), deleted.Revision); !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
					t.Fatalf("update after delete: %v", err)
				}
				mu.Lock()
				if string(deleted.Data) != string(last.Data) {
					t.Fatalf("deleted %q, but the last write was %q (rev %d)", deleted.Data, last.Data, last.Revision)
				}
				mu.Unlock()
			}
		})
	}
}

// A watch started before many concurrent writers sees each write once, in revision order, and
// the last event per key is the key's final state.
func TestStressWatchSeesEveryWriteInOrder(t *testing.T) {
	for name, open := range stores(t) {
		t.Run(name, func(t *testing.T) {
			s := open(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			rev, _ := s.Revision(ctx)
			ch, err := s.Watch(ctx, store.Selector{Kind: "Silo"}, rev)
			if err != nil {
				t.Fatal(err)
			}
			const writers, each = 6, 30
			var wg sync.WaitGroup
			var writes atomic.Int64
			for w := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					k := store.Key{Kind: "Silo", Namespace: "dev", Name: fmt.Sprintf("w%d", w)}
					if _, err := s.Create(ctx, k, []byte("0")); err != nil {
						t.Error(err)
						return
					}
					writes.Add(1)
					for i := 1; i < each; i++ {
						cur, err := s.Get(ctx, k)
						if err != nil {
							t.Error(err)
							return
						}
						if _, err := s.Update(ctx, k, []byte(strconv.Itoa(i)), cur.Revision); err != nil {
							t.Error(err)
							return
						}
						writes.Add(1)
					}
				}()
			}
			wg.Wait()
			want := writes.Load()
			var prev int64
			final := map[string]string{}
			for n := int64(0); n < want; n++ {
				select {
				case ev, ok := <-ch:
					if !ok {
						t.Fatalf("watch closed after %d of %d events", n, want)
					}
					if ev.Object.Revision <= prev {
						t.Fatalf("event at revision %d after %d", ev.Object.Revision, prev)
					}
					prev = ev.Object.Revision
					final[ev.Object.Name] = string(ev.Object.Data)
				case <-ctx.Done():
					t.Fatalf("%d of %d events", n, want)
				}
			}
			for w := range writers {
				if got := final[fmt.Sprintf("w%d", w)]; got != strconv.Itoa(each-1) {
					t.Fatalf("w%d's last event says %q, want %d", w, got, each-1)
				}
			}
		})
	}
}
