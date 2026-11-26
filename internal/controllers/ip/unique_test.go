package ip_test

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
	ipctl "kevaso.com/core/internal/controllers/ip"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// The same shape as K-028 for a host's extra addresses: two IPs naming one host address, each
// reconciled by its own controller (an old leader and a new one) on caches that don't show each
// other's writes, must not both get the address. One address on two IPs is traffic for one
// silo going to another.
func TestHostAddressesAreOneIPsByTheStoreAcrossLeaders(t *testing.T) {
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
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "h1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	h.Spec.Addresses = []v1.HostAddress{{Name: "a1", Kind: v1.NetworkExternal, Address: "198.51.100.17"}}
	must(c.Create(ctx, h))
	for _, n := range []string{"a", "b"} {
		must(c.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: n, Namespace: "d", Finalizers: []string{v1.FinalizerIP}},
			Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "a1"}}))
	}
	frozen := func(kind string) *informer.Informer {
		ictx, stop := context.WithCancel(ctx)
		inf := informer.New(c, kind)
		go inf.Run(ictx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		stop()
		return inf
	}
	ctl := func() *ipctl.Controller {
		return &ipctl.Controller{Client: c, IPs: frozen("IP"), Silos: frozen("Silo"), Services: frozen("Service"), Hosts: frozen("Host"),
			Claims: &claims.Claims{Store: st}}
	}
	one, two := ctl(), ctl()
	if _, err := one.Reconcile(ctx, engine.Key{Namespace: "d", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := two.Reconcile(ctx, engine.Key{Namespace: "d", Name: "b"}); err != nil {
		t.Fatal(err)
	}
	var a, b v1.IP
	must(c.Get(ctx, "IP", "d", "a", &a))
	must(c.Get(ctx, "IP", "d", "b", &b))
	if a.Status.Address != "198.51.100.17" {
		t.Fatalf("a, first, has no address: %+v", a.Status)
	}
	if b.Status.Address != "" {
		t.Fatalf("a and b were both given %s", b.Status.Address)
	}
	if r := meta.FindCondition(b.Status.Conditions, "Reserved"); r == nil || r.Reason != "Taken" {
		t.Fatalf("b doesn't say the address is another IP's: %+v", b.Status.Conditions)
	}
}
