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

// K-027, the controller's own guard: given a Silo cache that has not loaded its first list, the
// IP controller must not take "no claimant seen" for "no claimant", so a bound IP stays bound
// and is not deleted, whoever runs it and however it was started.
func TestK027IPControllerActsOnlyOnSyncedClaimCaches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
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
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 2, Memory: "4Gi"},
			Ports:   []v1.SiloPort{{Name: "http", Port: 80}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", LoadBalancer: true}}, LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool}}}}
	must(c.Create(ctx, s))
	name, _ := v1.SiloServiceIP(s, true)
	ip := &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d", Finalizers: []string{v1.FinalizerIP},
		OwnerReferences: []meta.OwnerReference{{APIVersion: v1.APIVersion, Kind: "Silo", Name: s.Name, UID: s.UID, Controller: true}}},
		Spec: v1.IPSpec{Class: v1.LBIPPool, Reclaim: v1.ReclaimDelete}}
	must(c.Create(ctx, ip))
	ip.Status.BoundTo = []v1.IPHolder{{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID, Ports: []string{"http"}}}
	must(c.UpdateStatus(ctx, ip))

	ips := informer.New(c, "IP")
	go ips.Run(ctx)
	if !ips.WaitSynced(ctx) {
		t.Fatal("IP cache never synced")
	}
	notYet := informer.New(c, "Silo") // never started: no first list
	ctl := &ipctl.Controller{Client: c, IPs: ips, Silos: notYet}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: name}); err != nil {
		t.Fatal(err)
	}
	var now v1.IP
	if err := c.Get(ctx, "IP", "d", name, &now); err != nil {
		t.Fatalf("the IP is gone: %v", err)
	}
	if now.DeletionTimestamp != nil || len(now.Status.BoundTo) != 1 || now.ResourceVersion != ip.ResourceVersion {
		t.Fatalf("acted on an unsynced Silo cache: deleting %v, bound to %v", now.DeletionTimestamp != nil, now.Status.BoundTo)
	}
}
