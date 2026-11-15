package silo_test

import (
	"context"
	"testing"
	"time"

	"kevaso.com/core/api/informer"
)

// cacheShows waits for inf to show what ok asks for (a write the test just made): the tests that
// use it drive every reconcile themselves, so nothing they assert depends on how fast a loaded
// machine runs an engine, only on the cache seeing a write, which ctx bounds as a safety net.
func cacheShows(ctx context.Context, t *testing.T, inf *informer.Informer, namespace, name string, ok func(any) bool) {
	t.Helper()
	for {
		if o, found := inf.Get(namespace, name); found && ok(o) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("the cache never showed %s/%s as expected", namespace, name)
		case <-time.After(2 * time.Millisecond):
		}
	}
}
