package service_test

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
	"kevaso.com/core/internal/controllers/service"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/store"
)

// frozen is an informer that has its first list and then hears nothing more: a cache as far
// behind as it can be (the watch has not delivered yet, or another leader wrote).
func frozen(ctx context.Context, t *testing.T, c *client.Client, kind string) *informer.Informer {
	t.Helper()
	ictx, stop := context.WithCancel(ctx)
	inf := informer.New(c, kind)
	go inf.Run(ictx)
	if !inf.WaitSynced(ctx) {
		t.Fatalf("%s never synced", kind)
	}
	stop()
	return inf
}

// K-028: Services decided from a cache that does not show each other's status yet (back to back,
// or by two controllers) must still get different cluster IPs and node ports: the store decides.
func TestK028ClusterIPsAndNodePortsAreUniqueByTheStore(t *testing.T) {
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
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a", "b"} {
		if err := c.Create(ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: n, Namespace: "d"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": n}, Ports: []v1.ServicePortSpec{{Name: "http", Port: 80}},
				Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "some-plugin"}}}); err != nil {
			t.Fatal(err)
		}
	}
	svcs, silos := frozen(ctx, t, c, "Service"), frozen(ctx, t, c, "Silo")
	// Two controllers on the same stale cache: each the other's "second leader".
	one := &service.Controller{Client: c, Services: svcs, Silos: silos, Claims: &claims.Claims{Store: st}}
	two := &service.Controller{Client: c, Services: svcs, Silos: silos, Claims: &claims.Claims{Store: st}}
	if _, err := one.Reconcile(ctx, engine.Key{Kind: "Service", Namespace: "d", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := two.Reconcile(ctx, engine.Key{Kind: "Service", Namespace: "d", Name: "b"}); err != nil {
		t.Fatal(err)
	}
	var a, b v1.Service
	if err := c.Get(ctx, "Service", "d", "a", &a); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Service", "d", "b", &b); err != nil {
		t.Fatal(err)
	}
	if a.Status.ClusterIP == "" || b.Status.ClusterIP == "" || len(a.Status.NodePorts) != 1 || len(b.Status.NodePorts) != 1 {
		t.Fatalf("not allocated: a %+v, b %+v", a.Status, b.Status)
	}
	if a.Status.ClusterIP == b.Status.ClusterIP {
		t.Errorf("a and b were both given cluster IP %s", a.Status.ClusterIP)
	}
	if a.Status.NodePorts[0].NodePort == b.Status.NodePorts[0].NodePort {
		t.Errorf("a and b were both given node port %d", a.Status.NodePorts[0].NodePort)
	}
}
