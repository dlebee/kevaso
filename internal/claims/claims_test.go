package claims

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"kevaso.com/core/internal/store"
)

type obj struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	Value string `json:"value"`
}

func uses(data []byte, value string) bool {
	var o obj
	return json.Unmarshal(data, &o) == nil && o.Value == value
}

func stores(t *testing.T) map[string]store.Store {
	sq, err := store.OpenSQLite(filepath.Join(t.TempDir(), "s.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sq.Close() })
	return map[string]store.Store{"memory": store.NewMemory(0), "sqlite": sq}
}

// put writes a holder object (kind Thing) and returns its revision as a version string.
func put(t *testing.T, st store.Store, name, uid, value string) string {
	t.Helper()
	var o obj
	o.Metadata.UID, o.Value = uid, value
	b, _ := json.Marshal(o)
	k := store.Key{Kind: "Thing", Name: name}
	cur, err := st.Get(context.Background(), k)
	var w store.Object
	if err == nil {
		w, err = st.Update(context.Background(), k, b, cur.Revision)
	} else {
		w, err = st.Create(context.Background(), k, b)
	}
	if err != nil {
		t.Fatal(err)
	}
	return strconv.FormatInt(w.Revision, 10)
}

func TestTakeIsUniqueAndTakesOverOnlyWhatIsNoLongerUsed(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			c := &Claims{Store: st}
			a := Holder{Kind: "Thing", Name: "a", UID: "ua", Version: put(t, st, "a", "ua", "")}
			b := Holder{Kind: "Thing", Name: "b", UID: "ub", Version: put(t, st, "b", "ub", "")}
			take := func(h Holder, v string) bool {
				t.Helper()
				ok, _, err := c.Take(ctx, "p", v, h, uses)
				if err != nil {
					t.Fatal(err)
				}
				return ok
			}
			if !take(a, "1") {
				t.Fatal("a can't take 1")
			}
			if !take(a, "1") {
				t.Fatal("a can't take 1 again")
			}
			// a claimed and has not written yet: b may not have it.
			if take(b, "1") {
				t.Fatal("b took a value a claimed and is about to write")
			}
			// a wrote it: still a's.
			a.Version = put(t, st, "a", "ua", "1")
			if take(b, "1") {
				t.Fatal("b took a value a uses")
			}
			// a was written since and no longer has it: b may take it over.
			put(t, st, "a", "ua", "2")
			if !take(b, "1") {
				t.Fatal("b can't take a value a let go of")
			}
			// a holder that is gone, or a new object under its name, holds nothing.
			if !take(a, "3") {
				t.Fatal("a can't take 3")
			}
			put(t, st, "a", "other-uid", "3")
			if !take(b, "3") {
				t.Fatal("b can't take a value held by a holder that is gone")
			}
			// LetGo removes the holder's other claims only.
			if !take(b, "4") {
				t.Fatal("b can't take 4")
			}
			if err := c.LetGo(ctx, "p", "ub", "4"); err != nil {
				t.Fatal(err)
			}
			objs, _, _ := st.List(ctx, store.Selector{Kind: Kind, Namespace: "p"})
			if len(objs) != 1 || objs[0].Name != "4" {
				t.Fatalf("after LetGo: %v", objs)
			}
		})
	}
}

// Many takers at once on one value: exactly one wins.
func TestTakeHasOneWinner(t *testing.T) {
	ctx := context.Background()
	for name, st := range stores(t) {
		t.Run(name, func(t *testing.T) {
			c := &Claims{Store: st}
			var hs []Holder
			for i := range 8 {
				n := strconv.Itoa(i)
				hs = append(hs, Holder{Kind: "Thing", Name: n, UID: "u" + n, Version: put(t, st, n, "u"+n, "")})
			}
			var mu sync.Mutex
			won := 0
			var wg sync.WaitGroup
			for _, h := range hs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ok, _, err := c.Take(ctx, "p", "x", h, uses)
					if err != nil && err != ErrBusy {
						t.Error(err)
					}
					if ok {
						mu.Lock()
						won++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			if won != 1 {
				t.Fatalf("%d winners", won)
			}
		})
	}
}
