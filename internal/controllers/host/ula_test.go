package host_test

import (
	"context"
	"net/http/httptest"
	"net/netip"
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

// The IPv6 effort: the cluster's ULA /48 is made once and stored; every later read (another
// leader, a restart) gets the same one.
func TestTheClusterULAIsMadeOnceAndKept(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	if got, err := hostctl.ReadULA(ctx, st); err != nil || got != "" {
		t.Fatalf("before any host: %q, %v; want none", got, err)
	}
	first, err := hostctl.EnsureULA(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := mesh.CheckULA(netip.MustParsePrefix(first)); err != nil {
		t.Fatalf("stored %s: %v", first, err)
	}
	for range 3 {
		again, err := hostctl.EnsureULA(ctx, st)
		if err != nil || again != first {
			t.Fatalf("again: %q, %v; want the stored %s", again, err, first)
		}
	}
}

// Each host gets its silo /64 from the cluster's /48 by its index, beside its IPv4 subnet; one
// rewritten in its status is put back, like the IPv4 addresses.
func TestTheHostControllerGivesEachHostItsIPv6Subnet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	for _, n := range []string{"hv1", "hv2"} {
		if err := c.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0." + n[2:], Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
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
	reconcile := func(name string) v1.Host {
		t.Helper()
		ctl := &hostctl.Controller{Client: c, Hosts: frozen(), Clock: clock.Real{}, Claims: &claims.Claims{Store: st}}
		if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "Host", Name: name}); err != nil {
			t.Fatal(err)
		}
		var h v1.Host
		if err := c.Get(ctx, "Host", "", name, &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h1, h2 := reconcile("hv1"), reconcile("hv2")
	ula, err := hostctl.ReadULA(ctx, st)
	if err != nil || ula == "" {
		t.Fatalf("no ULA stored: %v", err)
	}
	for _, h := range []v1.Host{h1, h2} {
		if want := mesh.SubnetIPv6(ula, h.Status.Network.Index); h.Status.Network.SiloSubnetIPv6 != want || want == "" {
			t.Fatalf("%s (index %d): siloSubnetIPv6 %q, want %q", h.Name, h.Status.Network.Index, h.Status.Network.SiloSubnetIPv6, want)
		}
	}
	if h1.Status.Network.SiloSubnetIPv6 == h2.Status.Network.SiloSubnetIPv6 {
		t.Fatalf("two hosts share %s", h1.Status.Network.SiloSubnetIPv6)
	}
	h1.Status.Network.SiloSubnetIPv6 = "fd00:dead:beef:1::/64"
	if err := c.UpdateStatus(ctx, &h1); err != nil {
		t.Fatal(err)
	}
	if got := reconcile("hv1"); got.Status.Network.SiloSubnetIPv6 != mesh.SubnetIPv6(ula, got.Status.Network.Index) {
		t.Fatalf("a rewritten /64 stayed: %s", got.Status.Network.SiloSubnetIPv6)
	}
}
