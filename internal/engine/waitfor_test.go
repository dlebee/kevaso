package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/internal/clock"
)

// cache is a Cache whose first list arrives when loaded is closed.
type cache struct {
	kind   string
	loaded chan struct{}
	done   atomic.Bool
}

func (c *cache) Kind() string { return c.kind }
func (c *cache) WaitSynced(ctx context.Context) bool {
	select {
	case <-c.loaded:
		c.done.Store(true)
		return true
	case <-ctx.Done():
		return false
	}
}

// K-027: with caches to wait for, no controller reconciles before every one of them has synced,
// and the changes that came meanwhile are not lost.
func TestK027RunHoldsControllersUntilEveryCacheSynced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	e := New(clock.Real{})
	f := newFake("IP")
	f.started = make(chan Key, 1)
	e.Register(f, Options{})
	a, b := &cache{kind: "IP", loaded: make(chan struct{})}, &cache{kind: "Silo", loaded: make(chan struct{})}
	e.WaitFor(a, b)
	waiting := make(chan []string, 1)
	e.OnWait = func(kinds []string) { waiting <- kinds }

	e.Changed(Key{Kind: "IP", Namespace: "d", Name: "x"})
	go e.Run(ctx)
	if k := <-waiting; len(k) != 2 || k[0] != "IP" || k[1] != "Silo" {
		t.Fatalf("waits for %v", k)
	}
	close(a.loaded)
	close(b.loaded)
	select {
	case k := <-f.started:
		if !a.done.Load() || !b.done.Load() {
			t.Fatalf("reconciled %s before every cache synced", k)
		}
	case <-ctx.Done():
		t.Fatal("the change queued before the caches synced was never reconciled")
	}
}
