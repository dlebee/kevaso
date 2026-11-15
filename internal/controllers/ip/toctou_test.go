package ip_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// Review (check-then-act) item 7: the IP controller lets go of a balancer (parks it, or deletes
// it for a class that reserves) when its cache shows no holder left. A silo that claims the IP
// after that read must not lose the balancer: before letting go, the claimants are read fresh
// and the decision made again; with a holder there, nothing is let go.
func TestALetGoDecidedFromACacheSparesAHolderThatCameSince(t *testing.T) {
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
	dir, _ := os.MkdirTemp("/tmp", "kvp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	must(reg.Add(ctx, fake))
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	mk := func(name string) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports:   []v1.SiloPort{{Name: "http", Port: 80}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "http", LoadBalancer: true}}, LoadBalancer: &v1.LoadBalancerSpec{Class: kplugintest.ClassLB, IP: "shared"}}}}
		must(c.Create(ctx, s))
		return s
	}
	a := mk("a")
	ip := &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "shared", Namespace: "d", Finalizers: []string{v1.FinalizerIP}},
		Spec: v1.IPSpec{Class: kplugintest.ClassLB, Reclaim: v1.ReclaimRetain}}
	must(c.Create(ctx, ip))
	ip.Status.BoundTo = []v1.IPHolder{{Holder: v1.HolderSiloPrefix + a.Name, UID: a.UID, Ports: []string{"http"}}}
	ip.Status.Address = "198.51.100.7"
	must(c.UpdateStatus(ctx, ip))
	must(c.Delete(ctx, "Silo", "d", "a"))
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
	ctl := &ipctl.Controller{Client: c, IPs: frozen("IP"), Silos: frozen("Silo"), Services: frozen("Service"), Hosts: frozen("Host"), Plugins: reg, Clock: clock.Real{}}
	mk("b") // claims the IP after the controller's read
	mark := len(fake.CallLog())
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "shared"}); err != nil {
		t.Fatal(err)
	}
	for _, call := range fake.CallLog()[mark:] {
		if strings.HasPrefix(call, "ensure-lb") || strings.HasPrefix(call, "delete-lb") {
			t.Fatalf("let go of the balancer of an IP a silo claims now: %q", call)
		}
	}
	var now v1.IP
	must(c.Get(ctx, "IP", "d", "shared", &now))
	if len(now.Status.BoundTo) == 0 {
		t.Fatalf("unbound although b holds it now: %+v", now.Status)
	}
}
