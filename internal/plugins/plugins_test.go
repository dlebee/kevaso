package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A plugin's socket appearing registers it over gRPC; it going away drops it.
func TestRegistryFindsSockets(t *testing.T) {
	dir, _ := os.MkdirTemp("", "kpr")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan struct{}, 8)
	r := &Registry{Dir: dir, Every: 20 * time.Millisecond, OnChange: func() { changes <- struct{}{} }}
	go r.Run(ctx)
	pctx, stop := context.WithCancel(ctx)
	sock := filepath.Join(dir, "fake", "plugin.sock")
	go func() { _ = kplugin.Serve(pctx, sock, kplugintest.New()) }()
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("never registered")
	}
	if p, c, ok := r.Storage("fake-block"); !ok || p.Info.Name != "fake" || !c.OwnHostsOnly {
		t.Fatalf("storage class: %v %+v", ok, c)
	}
	if _, ok := r.DNS("fake-dns"); !ok {
		t.Fatal("dns provider")
	}
	stop()
	_ = os.Remove(sock)
	select {
	case <-changes:
	case <-time.After(5 * time.Second):
		t.Fatal("never dropped")
	}
	if len(r.All()) != 0 {
		t.Fatalf("still registered: %v", r.All())
	}
}
