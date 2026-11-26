package ip_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

func tm(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

// An IP of type Host takes the address of the host's extra address it names, by name: none
// while no host has it (saying how to add one), the address once a host has it.
func TestHostIPTakesItsHostsAddressByName(t *testing.T) {
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
	must(c.Create(ctx, h))
	must(c.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "d", Finalizers: []string{v1.FinalizerIP}},
		Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail-a"}}))
	run := func(kind string) *informer.Informer {
		inf := informer.New(c, kind)
		go inf.Run(ctx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		return inf
	}
	ctl := &ipctl.Controller{Client: c, IPs: run("IP"), Silos: run("Silo"), Services: run("Service"), Hosts: run("Host")}
	reconcile := func() v1.IP {
		t.Helper()
		if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "mail"}); err != nil {
			t.Fatal(err)
		}
		var x v1.IP
		must(c.Get(ctx, "IP", "d", "mail", &x))
		return x
	}
	x := reconcile()
	r := meta.FindCondition(x.Status.Conditions, "Reserved")
	if x.Status.Address != "" || r == nil || r.Reason != "NoAddress" || !strings.Contains(r.Message, "kvoadm host addresses HOST add mail-a ADDRESS") {
		t.Fatalf("no host has it: %+v", x.Status)
	}
	must(c.Get(ctx, "Host", "", "h1", h))
	h.Spec.Addresses = []v1.HostAddress{{Name: "mail-a", Kind: v1.NetworkExternal, Address: "198.51.100.17"}}
	must(c.Update(ctx, h))
	for i := 0; ; i++ {
		if o, ok := ctl.Hosts.Get("", "h1"); ok && len(o.(*v1.Host).Spec.Addresses) == 1 {
			break
		}
		if i == 100 {
			t.Fatal("the host cache never saw the address")
		}
		time.Sleep(20 * time.Millisecond)
	}
	x = reconcile()
	if x.Status.Address != "198.51.100.17" || x.Status.Host != "h1" || x.Status.Where != "host h1" {
		t.Fatalf("the host's address: %+v", x.Status)
	}
}

// An IP of type Provider is reserved from the plugin of that name, in its region, and released
// when the IP is deleted.
func TestProviderIPReservedAndReleased(t *testing.T) {
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
	must(c.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "eth", Namespace: "d", Finalizers: []string{v1.FinalizerIP}},
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "r1"}}))
	run := func(kind string) *informer.Informer {
		inf := informer.New(c, kind)
		go inf.Run(ctx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		return inf
	}
	ctl := &ipctl.Controller{Client: c, IPs: run("IP"), Silos: run("Silo"), Services: run("Service"), Hosts: run("Host"), Plugins: reg}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "eth"}); err != nil {
		t.Fatal(err)
	}
	var x v1.IP
	must(c.Get(ctx, "IP", "d", "eth", &x))
	if x.Status.Address != "203.0.113.100" || x.Status.Region != "r1" || x.Status.Handle == "" || x.Status.Where != "fake r1" {
		t.Fatalf("reserved: %+v", x.Status)
	}
	must(c.Delete(ctx, "IP", "d", "eth"))
	for i := 0; ; i++ {
		if o, ok := ctl.IPs.Get("d", "eth"); ok && o.GetObjectMeta().DeletionTimestamp != nil {
			break
		}
		if i == 100 {
			t.Fatal("the IP cache never saw the delete")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "eth"}); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(fake.CallLog(), func(s string) bool { return strings.HasPrefix(s, "release-address "+kplugintest.ClassIP) }) {
		t.Fatalf("not released: %v", fake.CallLog())
	}
	if err := c.Get(ctx, "IP", "d", "eth", &x); !client.IsNotFound(err) {
		t.Fatalf("the IP is still there: %v %+v", err, x.ObjectMeta)
	}
}
