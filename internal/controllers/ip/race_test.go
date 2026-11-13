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
	"kevaso.com/core/internal/clock"
	ipctl "kevaso.com/core/internal/controllers/ip"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

func tm(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

// Two ip-pool IPs reconciled back to back, the second before the informer has seen the first
// one's address (a watch is never instant): they must not get the same address. One address on
// two hosts' silos is traffic for one going to the other.
func TestPoolAddressesNeverHandedOutTwice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel() // the informers' watches end before the server closes
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
	h.Spec.Network.Addresses = []string{"198.51.100.16/30"}
	must(c.Create(ctx, h))
	for _, n := range []string{"a", "b"} {
		must(c.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: n, Namespace: "d"},
			Spec: v1.IPSpec{Class: v1.LBIPPool}}))
	}
	run := func(kind string) *informer.Informer {
		inf := informer.New(c, kind)
		go inf.Run(ctx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		return inf
	}
	ctl := &ipctl.Controller{Client: c, IPs: run("IP"), Silos: run("Silo"), Services: run("Service"), Hosts: run("Host")}
	settle := func(name string) {
		for i := 0; i < 50; i++ {
			if o, ok := ctl.IPs.Get("d", name); ok && len(o.GetObjectMeta().Finalizers) > 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	// The finalizers first (each a write and a fresh read), as the controller does.
	for _, n := range []string{"a", "b"} {
		if _, err := ctl.Reconcile(ctx, engine.Key{Namespace: "d", Name: n}); err != nil {
			t.Fatal(err)
		}
		settle(n)
	}
	// Now back to back, as one worker takes the next key off the queue at once.
	for _, n := range []string{"a", "b"} {
		if _, err := ctl.Reconcile(ctx, engine.Key{Namespace: "d", Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	var a, b v1.IP
	must(c.Get(ctx, "IP", "d", "a", &a))
	must(c.Get(ctx, "IP", "d", "b", &b))
	if a.Status.Address == "" || b.Status.Address == "" {
		t.Fatalf("no address: a %q, b %q", a.Status.Address, b.Status.Address)
	}
	if a.Status.Address == b.Status.Address {
		t.Fatalf("a and b were both given %s", a.Status.Address)
	}
}
