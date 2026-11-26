package provider_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// A silo's load-balancer address is said twice in its status: service.loadBalancerIP and each
// load-balanced port's loadBalancer. The balancer writes the address; every version it stores
// must say the same in both, so no reader (kvo describe, kvo ips, kvo probe) sees an address with
// no port on it, or a port on an address taken away. TestIPs read such a version ("out X,
// nothing in") between the balancer's write and the scheduler's next one.
func TestBalancerWritesTheAddressOnTheSilosPortsToo(t *testing.T) {
	t.Skip("TODO(net-v2 wave 2): the balancer controller (provider.Balancers) writes a LoadBalancer service's address")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	defer cancel() // the informers first
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
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
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
	must(c.Create(ctx, h))
	h.Status.Provider = &v1.HostProvider{Name: "fake", ID: "42", Region: "r"}
	h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
	must(c.UpdateStatus(ctx, h))

	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "node", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports: []v1.SiloPort{{Name: "p2p", Port: 30303}},
			Services: []v1.SiloService{{Type: v1.ServiceLoadBalancer, Ports: []v1.ServicePort{{Port: "p2p"}},
				LoadBalancer: &v1.LoadBalancerSpec{Provider: "fake", IP: "eth"}}}}}
	must(c.Create(ctx, s))
	x := &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "eth", Namespace: "d"},
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "r"}}
	must(c.Create(ctx, x))
	_, err = fake.ReserveAddress(ctx, kplugin.AddressReservation{Class: kplugintest.ClassIP, ID: x.UID, Region: "r", Address: "203.0.113.100"})
	must(err)
	x.Status.Address, x.Status.Region = "203.0.113.100", "r"
	x.Status.Holder = &v1.IPHolder{Holder: v1.HolderSiloPrefix + "node", UID: s.UID, Ports: []string{"30303/TCP"}}
	must(c.UpdateStatus(ctx, x))
	// Placed on w1 by the scheduler: its ports, no address in yet (the balancer's to write).
	s.Status.Host, s.Status.Phase = "w1", "Scheduled"
	s.Status.Service.IP = "eth"
	s.Status.Service.Ports = scheduler.PortStatus(s, h, "")
	must(c.UpdateStatus(ctx, s))

	synced := func(kind string) *informer.Informer {
		inf := informer.New(c, kind)
		go inf.Run(ctx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		return inf
	}
	ctl := &provider.Balancers{Client: c, IPs: synced("IP"), Silos: synced("Silo"), Services: synced("Service"), Hosts: synced("Host"), Plugins: reg}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "eth"}); err != nil {
		t.Fatal(err)
	}
	var cur v1.Silo
	must(c.Get(ctx, "Silo", "d", "node", &cur))
	st := cur.Status.Service
	if st.LoadBalancerIP != "203.0.113.100" {
		t.Fatalf("the balancer wrote no address: %+v", st)
	}
	if len(st.Ports) != 1 || st.Ports[0].LoadBalancer != "203.0.113.100:30303" {
		t.Errorf("loadBalancerIP %s, but its port says %+v", st.LoadBalancerIP, st.Ports)
	}

	// The address taken away (another holds it now, says the IP): off both, in one write.
	must(c.Get(ctx, "IP", "d", "eth", x))
	x.Status.Holder = &v1.IPHolder{Holder: v1.HolderSiloPrefix + "other", UID: "other-uid"}
	x.Status.Waiting = []v1.IPWaiting{{Holder: v1.HolderSiloPrefix + "node", Reason: "held by silo/other"}}
	must(c.UpdateStatus(ctx, x))
	for {
		if o, ok := ctl.IPs.Get("d", "eth"); ok && len(o.(*v1.IP).Status.Waiting) == 1 {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("the IP cache never saw the change")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "IP", Namespace: "d", Name: "eth"}); err != nil {
		t.Fatal(err)
	}
	var after v1.Silo // a fresh one: decoding into cur would keep what the JSON leaves out
	must(c.Get(ctx, "Silo", "d", "node", &after))
	st = after.Status.Service
	if st.LoadBalancerIP != "" || len(st.Ports) != 1 || st.Ports[0].LoadBalancer != "" {
		t.Errorf("taken away: loadBalancerIP %q, ports %+v", st.LoadBalancerIP, st.Ports)
	}
}
