package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
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
	c, closeC := workerClient(srv, st, wm, "cp-1")
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

// Review of the control-plane fixes, items 1 and 2: the worker on a system node writes as its
// host (a worker), never as the control plane's own Component: so what it may write is judged as
// a worker-only host's is (HostWrite: only the source lets go of a handoff; it may not rewrite its
// status.provider or its mesh addresses).
func TestTheWorkerOnASystemNodeWritesAsItsHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}})
	if err != nil {
		t.Fatal(err)
	}
	c, closeC := workerClient(srv, st, agent.OpenWatermark("", nil), "cp-1")
	defer closeC()
	c.ControlPlane = nil // the store holds no identity to stamp with here
	var who client.WhoAmI
	if err := c.Call(ctx, "POST", "/auth/whoami", map[string]string{}, &who); err != nil {
		t.Fatal(err)
	}
	if who.Type != "host" || who.Name != "cp-1" || who.Role != "worker" {
		t.Fatalf("the system node's worker is %+v, want host cp-1 as a worker", who)
	}
}

// The worker on a real system node (controlplane.Start with a worker component), writing as its
// host: everything it writes is accepted (its Host's worker status reaches the store), none of it
// is refused as a host's write it may not make.
func TestASystemNodesWorkerRunsAsItsHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvw")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var mu sync.Mutex
	var logs []string
	logf := func(f string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	r, err := Start(ctx, Config{ClusterName: "test", HostName: "cp-1", InternalIP: "127.0.0.1", DataDir: filepath.Join(dir, "d"),
		Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 50 * time.Millisecond, Create: true, Log: logf,
		Worker: &worker.Config{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = r.Wait() }()
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	for {
		var h v1.Host
		if err := admin.Get(ctx, "Host", "", "cp-1", &h); err == nil && h.Status.Allocatable.CPU > 0 {
			break
		}
		select {
		case <-ctx.Done():
			mu.Lock()
			t.Fatalf("the system node's worker never reported its Host; log:\n%s", strings.Join(logs, "\n"))
		case <-time.After(20 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logs {
		if strings.Contains(l, "Forbidden") || strings.Contains(l, "(403)") {
			t.Fatalf("a write of the system node's worker was refused: %s", l)
		}
	}
}

// Review of the control-plane fixes, item 3: the worker on a system node got its answers through
// the stamping middleware without its refusal: a write whose stamp couldn't be read (the store
// slow past StampTimeout) was still made, its answer came back unstamped, the client called it
// NotYet, and the worker sent again a write that had landed. It is refused before anything is
// handled, as on the API listener: nothing is made, and sending again is safe.
func TestTheSystemNodesWorkerNeverHasAWriteMadeWithoutAStamp(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	b, _ := json.Marshal(ClusterIdentity{ID: "c", History: "h1", Epoch: 1})
	if _, err := st.Create(ctx, identityKey, b); err != nil {
		t.Fatal(err)
	}
	slow := noRevision{st} // its revision can't be read: the stamp can't be made
	srv, err := apiserver.New(slow, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	c, closeC := workerClient(srv, slow, agent.OpenWatermark("", nil), "cp-1")
	defer closeC()
	err = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	if !client.IsUnavailable(err) {
		t.Fatalf("a write with no stamp possible: %v, want refused as unavailable before it is made", err)
	}
	if _, err := st.Get(ctx, store.Key{Kind: "Namespace", Name: "dev"}); err == nil {
		t.Fatal("the write was made although its answer couldn't be stamped: sending it again makes it twice")
	}
}
