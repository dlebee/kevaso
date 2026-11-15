package informer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-062: a kevasod that starts while the control plane is away starts from what it kept. A
// seeded cache serves what was known then, and says it isn't synced (an object missing from it
// may exist, one in it may be gone): nothing that removes things trusts it. The first list
// replaces it.
func TestASeededCacheServesWhatWasKnownUntilTheFirstList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "away", http.StatusServiceUnavailable) // the control plane is away
	}))
	defer ts.Close()
	i := New(client.New(ts.URL), "Silo")
	kept := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev", ResourceVersion: "7"}}
	i.Seed([]meta.Object{kept})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go i.Run(ctx)
	if !i.WaitReady(ctx) {
		t.Fatal("a seeded cache isn't ready")
	}
	if _, ok := i.Get("dev", "web"); !ok || len(i.List()) != 1 {
		t.Fatal("the seed isn't served")
	}
	time.Sleep(200 * time.Millisecond)
	if i.Synced() {
		t.Fatal("a seed reads as a list: something would remove what it doesn't show")
	}
}
