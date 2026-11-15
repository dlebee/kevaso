package worker

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// §0.7, the worker's hold: while its control plane is older than what it saw (or another
// cluster's), the worker's own rules, routes and addresses stay as they are: nothing built
// from that control plane's state is loaded.
func TestAHeldWorkerLoadsNoRules(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	api := httptest.NewServer(srv)
	defer api.Close()
	admin := client.New(api.URL)
	_ = admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "198.51.100.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}})
	applied := make(chan string, 16)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error { applied <- rules; return nil }
	defer func() { applyRules = old }()
	var held atomic.Bool
	held.Store(true)
	done := make(chan struct{})
	go func() {
		RunNetworkHeld(ctx, client.New(api.URL), "hv1", nil, nil, func(string, ...any) {}, held.Load)
		close(done)
	}()
	defer func() { cancel(); <-done; api.CloseClientConnections() }()
	select {
	case <-applied:
		t.Fatal("rules loaded while held")
	case <-time.After(2 * time.Second):
	}
	held.Store(false)
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("no rules once the hold ended")
	}
}
