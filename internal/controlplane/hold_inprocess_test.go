package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// The worker on a system node talks to the API in-process, never through the TLS listener that
// stamps answers: it judged nothing, so a same-history downgrade of this node's store was applied
// on its host. Its client is stamped and judged like a worker-only host's.
func TestTheWorkerOnASystemNodeIsJudged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	b, _ := json.Marshal(ClusterIdentity{ID: "c", History: "h1", Epoch: 1})
	if _, err := st.Create(ctx, identityKey, b); err != nil {
		t.Fatal(err)
	}
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	// What this host's worker saw before: revision 1000 of history h1. The store now is far below.
	path := filepath.Join(t.TempDir(), "control-plane-watermark.json")
	kept, _ := json.Marshal(client.Watermark{ClusterID: "c", History: "h1", Epoch: 1, Revision: 1000})
	if err := os.WriteFile(path, kept, 0o600); err != nil {
		t.Fatal(err)
	}
	wm := agent.OpenWatermark(path, nil)
	c, closeC := workerClient(srv, st, wm)
	defer closeC()
	_ = c.Get(ctx, "Namespace", "", "default", &v1.Namespace{})
	if !wm.Held() {
		t.Fatal("the worker on a system node applied answers from a store older than what it saw: not held")
	}
	// A store caught up: the hold ends by itself.
	for i := 0; i < 1100; i++ {
		if _, err := st.Create(ctx, store.Key{Kind: "Filler", Name: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26))}, []byte("{}")); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.Get(ctx, "Namespace", "", "default", &v1.Namespace{})
	if wm.Held() {
		t.Fatal("still held once the store is past what was kept")
	}
}
