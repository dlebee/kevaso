package silo_test

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
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

// frozen is an informer that has its first list and then hears nothing more.
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

// K-029: two silos placed back to back on one host, before the cache shows the first one's
// status, must not get the same node port or the same host port: the store decides, and the
// second gets another node port, or (its host port held) another host.
func TestK029NodePortsAndHostPortsAreUniqueByTheStore(t *testing.T) {
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
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}))
	for _, n := range []string{"hv1", "hv2"} {
		h := readyHost(n)
		h.Spec.InternalIP = "10.0.0.1"
		h.Spec.Components.Worker.Labels = map[string]string{"name": n}
		must(c.Create(ctx, h))
		h.Status = readyHost(n).Status
		h.Status.Provider = &v1.HostProvider{Name: "nb", ID: n, Region: "r"} // a balancer is its provider's machines'
		must(c.UpdateStatus(ctx, h))
	}
	mk := func(name string, hostPort bool) *v1.Silo {
		s := newSilo(name)
		s.Spec.VM = &v1.VMSource{Image: "ubuntu-24.04"}
		s.Spec.Resources = v1.Resources{CPU: 1, Memory: "1Gi"}
		s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 80}}
		if hostPort {
			s.Spec.Services = []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal}, Ports: []v1.ServicePort{{Port: "http"}}}}
		} else { // both on hv1, where their node ports are handed out
			s.Spec.Placement.HostSelector = map[string]string{"name": "hv1"}
			s.Spec.Services = []v1.SiloService{{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "nb"}, Ports: []v1.ServicePort{{Port: "http"}}}}
		}
		must(c.Create(ctx, s))
		return s
	}
	mk("a", false)
	mk("b", false)
	mk("c", true)
	mk("d", true)
	classes := func() map[string]scheduler.Class {
		return map[string]scheduler.Class{"nb": {Plugin: "nb", NodePorts: true}}
	}
	ctl := func() *silo.Controller {
		return &silo.Controller{Client: c, Silos: frozen(ctx, t, c, "Silo"), Hosts: frozen(ctx, t, c, "Host"), IPs: frozen(ctx, t, c, "IP"), Clock: clock.Real{},
			Classes: classes, Claims: &claims.Claims{Store: st}}
	}
	one, two := ctl(), ctl() // the second as a new leader whose cache is as old as the first's
	for _, x := range []struct {
		c    *silo.Controller
		name string
	}{{one, "c"}, {two, "d"}, {one, "a"}, {one, "b"}} {
		if _, err := x.c.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: x.name}); err != nil {
			t.Fatal(err)
		}
	}
	get := func(name string) *v1.Silo {
		var s v1.Silo
		must(c.Get(ctx, "Silo", "dev", name, &s))
		return &s
	}
	a, b := get("a"), get("b")
	if a.Status.Host == "" || b.Status.Host == "" || len(a.Status.Service.NodePorts) != 1 || len(b.Status.Service.NodePorts) != 1 {
		t.Fatalf("not placed: a %+v, b %+v", a.Status, b.Status)
	}
	if a.Status.Service.NodePorts[0].NodePort == b.Status.Service.NodePorts[0].NodePort {
		t.Errorf("a and b were both given node port %d on %s", a.Status.Service.NodePorts[0].NodePort, a.Status.Host)
	}
	cs, d := get("c"), get("d")
	if cs.Status.Host == "" || d.Status.Host == "" {
		t.Fatalf("not placed: c on %q, d on %q", cs.Status.Host, d.Status.Host)
	}
	if cs.Status.Host == d.Status.Host {
		t.Errorf("c and d both hold port 80 on %s's internal IP", cs.Status.Host)
	}
}
