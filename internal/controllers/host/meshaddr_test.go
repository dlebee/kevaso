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
	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/store"
)

// Review of the control-plane fixes, item 2: a host's mesh address, silo subnet and inner address
// follow from the index the control plane assigned it (mesh.Addresses). One rewritten in its
// status (by anyone allowed to write it) is not what peers keep: the host controller puts the
// addresses of its index back.
func TestTheHostControllerPutsBackTheAddressesOfItsIndex(t *testing.T) {
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
	if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
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
	reconcile := func() v1.Host {
		t.Helper()
		ctl := &hostctl.Controller{Client: c, Hosts: frozen(), Clock: clock.Real{}, Claims: &claims.Claims{Store: st}}
		if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "Host", Name: "hv1"}); err != nil {
			t.Fatal(err)
		}
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "hv1", &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := reconcile()
	i := h.Status.Network.Index
	if i == 0 {
		t.Fatal("no index assigned")
	}
	h.Status.Network.MeshIP, h.Status.Network.SiloSubnet, h.Status.Network.InnerIP = "10.63.0.250", "10.64.250.0/24", "10.62.0.250"
	if err := c.UpdateStatus(ctx, &h); err != nil {
		t.Fatal(err)
	}
	h = reconcile()
	wantMesh, wantSubnet, wantInner := mesh.Addresses(i)
	if n := h.Status.Network; n.Index != i || n.MeshIP != wantMesh || n.SiloSubnet != wantSubnet || n.InnerIP != wantInner {
		t.Fatalf("index %d with %+v, want %s %s %s", i, n, wantMesh, wantSubnet, wantInner)
	}
}
