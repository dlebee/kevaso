package host_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/claims"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// The same shape as K-028 for hosts' mesh indexes: two controllers (an old leader and a new one)
// on caches that don't show each other's writes must not give two hosts one index (one mesh
// address and one silo subnet).
func TestMeshIndexesAreUniqueByTheStoreAcrossLeaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel()
	c := client.New(ts.URL)
	mk := func(n string) {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	frozen := func() *informer.Informer {
		ictx, stop := context.WithCancel(ctx)
		inf := informer.New(c, "Host")
		go inf.Run(ictx)
		if !inf.WaitSynced(ctx) {
			t.Fatal("never synced")
		}
		stop()
		return inf
	}
	// One controller's cache has hv2 only; the other's has hv1 and hv2, neither with an index
	// yet. Each would give its host index 1.
	mk("hv2")
	one := &hostctl.Controller{Client: c, Hosts: frozen(), Clock: clock.Real{}, Claims: &claims.Claims{Store: st}}
	mk("hv1")
	two := &hostctl.Controller{Client: c, Hosts: frozen(), Clock: clock.Real{}, Claims: &claims.Claims{Store: st}}
	if _, err := one.Reconcile(ctx, engine.Key{Kind: "Host", Name: "hv2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := two.Reconcile(ctx, engine.Key{Kind: "Host", Name: "hv1"}); err != nil {
		t.Fatal(err)
	}
	var a, b v1.Host
	if err := c.Get(ctx, "Host", "", "hv1", &a); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Host", "", "hv2", &b); err != nil {
		t.Fatal(err)
	}
	if a.Status.Network.Index == 0 || b.Status.Network.Index == 0 {
		t.Fatalf("no index: hv1 %d, hv2 %d", a.Status.Network.Index, b.Status.Network.Index)
	}
	if a.Status.Network.Index == b.Status.Network.Index {
		t.Fatalf("hv1 and hv2 were both given mesh index %d", a.Status.Network.Index)
	}
}
