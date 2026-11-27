package provider_test

import (
	"context"
	"errors"
	"fmt"
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
	"kevaso.com/core/internal/controllers/provider"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// lbEnv is an API server in memory with the fake plugin, two of its machines (w1, w2) and a host
// that isn't one (home), and the balancer controllers over synced caches.
type lbEnv struct {
	t    *testing.T
	ctx  context.Context
	c    *client.Client
	fake *kplugintest.Fake
	ctl  *provider.Balancers
	svcs provider.ServiceBalancers
	next int // the next node port
}

func newLBEnv(t *testing.T) *lbEnv {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	t.Cleanup(cancel) // the informers stop before the server closes
	c := client.New(ts.URL)
	dir, _ := os.MkdirTemp("/tmp", "kvb")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	e := &lbEnv{t: t, ctx: ctx, c: c, fake: fake}
	e.must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for i, n := range []string{"w1", "w2", "home"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{ExternalIP: fmt.Sprintf("203.0.113.%d", 5+i), Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		e.must(c.Create(ctx, h))
		if n != "home" {
			h.Status.Provider = &v1.HostProvider{Name: "fake", ID: fmt.Sprint(40 + i), Region: "ca-central"}
		}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: time.Now().UTC().Truncate(time.Second)}}
		e.must(c.UpdateStatus(ctx, h))
	}
	synced := func(kind string) *informer.Informer {
		inf := informer.New(c, kind)
		go inf.Run(ctx)
		if !inf.WaitSynced(ctx) {
			t.Fatalf("%s never synced", kind)
		}
		return inf
	}
	e.ctl = &provider.Balancers{Client: c, IPs: synced("IP"), Silos: synced("Silo"), Services: synced("Service"), Hosts: synced("Host"), Plugins: reg}
	e.svcs = provider.ServiceBalancers{Balancers: e.ctl}
	return e
}

func tm(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func (e *lbEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

// silo makes a running silo on host with one LoadBalancer service per name (port web, 8080,
// as 443), annotated, with its node ports.
func (e *lbEnv) silo(name, host string, ann map[string]string, services ...string) *v1.Silo {
	return e.siloIn(name, host, "Running", ann, services...)
}

func (e *lbEnv) siloIn(name, host, phase string, ann map[string]string, services ...string) *v1.Silo {
	e.t.Helper()
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}}}}
	for _, sv := range services {
		s.Spec.Services = append(s.Spec.Services, v1.SiloService{Name: sv, Type: v1.ServiceLoadBalancer, Annotations: ann,
			LoadBalancer: &v1.LoadBalancerSpec{Provider: "fake"}, Ports: []v1.ServicePort{{Port: "web", As: 443}}})
	}
	e.must(e.c.Create(e.ctx, s))
	e.place(s, host, phase)
	return s
}

// place puts s on host in phase, with its ports and node ports, as the scheduler and the worker would.
func (e *lbEnv) place(s *v1.Silo, host, phase string) {
	e.t.Helper()
	var h v1.Host
	e.must(e.c.Get(e.ctx, "Host", "", host, &h))
	e.must(e.c.Get(e.ctx, "Silo", s.Namespace, s.Name, s))
	s.Status.Host, s.Status.Phase, s.Status.SiloIP = host, phase, "10.64.0.9"
	s.Status.Service.Ports = scheduler.PortStatus(s, &h, s.Status.Service.LoadBalancerIP)
	if len(s.Status.Service.NodePorts) == 0 {
		e.next++
		s.Status.Service.NodePorts = []v1.NodePort{{Name: "web", Port: 443, NodePort: 30000 + e.next}}
	}
	e.must(e.c.UpdateStatus(e.ctx, s))
}

// reconcile runs the silo's balancers until done says so (the caches catch up in between).
func (e *lbEnv) reconcile(kind, name string, done func() (bool, string)) {
	e.t.Helper()
	last := ""
	for e.ctx.Err() == nil {
		var err error
		if kind == "Silo" {
			_, err = e.ctl.Reconcile(e.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: name})
		} else {
			_, err = e.svcs.Reconcile(e.ctx, engine.Key{Kind: "Service", Namespace: "d", Name: name})
		}
		ok, why := done()
		if ok {
			return
		}
		last = fmt.Sprintf("%s (reconcile: %v)", why, err)
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("%s %s: never happened; last: %s", kind, name, last)
}

func (e *lbEnv) get(name string) (*v1.Silo, bool) {
	var s v1.Silo
	err := e.c.Get(e.ctx, "Silo", "d", name, &s)
	if client.IsNotFound(err) {
		return nil, false
	}
	e.must(err)
	return &s, true
}

func lbCond(conds []meta.Condition) string {
	if c := meta.FindCondition(conds, "LoadBalancer"); c != nil {
		return string(c.Status) + " " + c.Reason + ": " + c.Message
	}
	return "no LoadBalancer condition"
}

// One balancer per service, keyed by the service: its ports go to the silo's host on its node
// ports, the address goes on the silo's status (and its port) with the balancer's ranges, and a
// finalizer holds the silo until the balancer is removed with it.
func TestBalancerPerServiceMadeAndRemovedWithTheSilo(t *testing.T) {
	e := newLBEnv(t)
	s := e.silo("shop", "w1", nil, "shop")
	addr := ""
	e.reconcile("Silo", "shop", func() (bool, string) {
		cur, _ := e.get("shop")
		addr = cur.Status.Service.LoadBalancerIP
		return addr != "" && meta.IsTrue(cur.Status.Conditions, "LoadBalancer"), lbCond(cur.Status.Conditions)
	})
	cur, _ := e.get("shop")
	if !slices.Contains(cur.Finalizers, "kevaso.com/balancer-fake.shop") {
		t.Errorf("finalizers %v: want the balancer's", cur.Finalizers)
	}
	if st := cur.Status.Service; len(st.Ports) != 1 || st.Ports[0].LoadBalancer != addr+":443" || !slices.Equal(st.SourceRanges, []string{"192.168.255.0/24"}) {
		t.Errorf("status %+v: want the address on the port too, and the balancer's ranges", st)
	}
	lbs, _, _ := e.fake.Snapshot()
	lb, ok := lbs[provider.SiloBalancerID(s, "shop")]
	if !ok || lb.Class != kplugintest.ClassLB || lb.Name != "shop" || len(lb.Ports) != 1 {
		t.Fatalf("balancers %+v: want one for service shop", lbs)
	}
	if p := lb.Ports[0]; p.Port != 443 || p.NodePort != 30001 || len(p.Backends) != 1 || p.Backends[0].Name != "w1" {
		t.Errorf("port %+v: want 443 to w1's node port 30001", p)
	}

	e.must(e.c.Delete(e.ctx, "Silo", "d", "shop"))
	e.reconcile("Silo", "shop", func() (bool, string) {
		cur, ok := e.get("shop")
		if !ok {
			return true, ""
		}
		return false, fmt.Sprint(cur.Finalizers)
	})
	if lbs, _, _ := e.fake.Snapshot(); len(lbs) != 0 {
		t.Errorf("balancers left after the silo: %+v", lbs)
	}
}

// A balancer answering on IPv6 too (a Linode NodeBalancer): its IPv6 address goes on the silo's
// status beside its IPv4, and comes off with it.
func TestBalancerIPv6OnTheSilosStatus(t *testing.T) {
	e := newLBEnv(t)
	e.fake.BalancerIPv6 = true
	e.silo("shop", "w1", nil, "shop")
	e.reconcile("Silo", "shop", func() (bool, string) {
		cur, _ := e.get("shop")
		st := cur.Status.Service
		return st.LoadBalancerIP == "198.51.100.10" && st.LoadBalancerIPv6 == "2001:db8:b::c633:640a" && meta.IsTrue(cur.Status.Conditions, "LoadBalancer"),
			fmt.Sprintf("%q %q %s", st.LoadBalancerIP, st.LoadBalancerIPv6, lbCond(cur.Status.Conditions))
	})
}

// Services naming the same shared balancer (the provider's annotation) get one address; one
// going leaves the other's; the last going removes it.
func TestBalancerSharedByAnnotation(t *testing.T) {
	e := newLBEnv(t)
	ann := map[string]string{"fake.kevaso.com/balancer": "edge"}
	e.silo("a", "w1", ann, "a")
	e.silo("b", "w2", ann, "b")
	e.silo("c", "w2", nil, "c")
	addr := map[string]string{}
	for _, n := range []string{"a", "b", "c"} {
		e.reconcile("Silo", n, func() (bool, string) {
			cur, _ := e.get(n)
			addr[n] = cur.Status.Service.LoadBalancerIP
			return addr[n] != "", lbCond(cur.Status.Conditions)
		})
	}
	if addr["a"] != addr["b"] || addr["a"] == addr["c"] {
		t.Fatalf("addresses %v: a and b share one, c has its own", addr)
	}
	e.must(e.c.Delete(e.ctx, "Silo", "d", "a"))
	e.reconcile("Silo", "a", func() (bool, string) { _, ok := e.get("a"); return !ok, "a still there" })
	_, _ = e.ctl.Reconcile(e.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "b"})
	if cur, _ := e.get("b"); cur.Status.Service.LoadBalancerIP != addr["b"] {
		t.Errorf("b's address after a went: %q, want %s", cur.Status.Service.LoadBalancerIP, addr["b"])
	}
}

// A service taken out of the silo (or no longer a LoadBalancer) has its balancer removed; the
// silo's others stay.
func TestBalancerRemovedWithItsService(t *testing.T) {
	e := newLBEnv(t)
	s := e.silo("two", "w1", nil, "one", "other")
	e.reconcile("Silo", "two", func() (bool, string) {
		lbs, _, _ := e.fake.Snapshot()
		return len(lbs) == 2, fmt.Sprint(len(lbs), " balancers")
	})
	cur, _ := e.get("two")
	cur.Spec.Services = cur.Spec.Services[:1]
	e.must(e.c.Update(e.ctx, cur))
	e.reconcile("Silo", "two", func() (bool, string) {
		cur, _ := e.get("two")
		lbs, _, _ := e.fake.Snapshot()
		_, kept := lbs[provider.SiloBalancerID(s, "one")]
		return len(lbs) == 1 && kept && !slices.Contains(cur.Finalizers, "kevaso.com/balancer-fake.other"), fmt.Sprint(cur.Finalizers, len(lbs))
	})
}

// A silo not running gets no balancer yet (its backend would be held back), and says why.
func TestBalancerWaitsForARoutedSilo(t *testing.T) {
	e := newLBEnv(t)
	s := e.siloIn("slow", "w1", "Starting", nil, "slow")
	e.reconcile("Silo", "slow", func() (bool, string) {
		cur, _ := e.get("slow")
		c := meta.FindCondition(cur.Status.Conditions, "LoadBalancer")
		return c != nil && c.Reason == "NotRouted", lbCond(cur.Status.Conditions)
	})
	if lbs, _, _ := e.fake.Snapshot(); len(lbs) != 0 {
		t.Errorf("a balancer for a silo not running: %+v", lbs)
	}
	// Not on the provider's machine: said so, no balancer.
	e.place(s, "home", "Running")
	e.reconcile("Silo", "slow", func() (bool, string) {
		cur, _ := e.get("slow")
		c := meta.FindCondition(cur.Status.Conditions, "LoadBalancer")
		return c != nil && c.Reason == "NotOnProvider", lbCond(cur.Status.Conditions)
	})
}

// A failing plugin keeps the finalizer: the silo stays until its balancer is removed, retried.
func TestBalancerRemovalRetried(t *testing.T) {
	e := newLBEnv(t)
	e.silo("x", "w1", nil, "x")
	e.reconcile("Silo", "x", func() (bool, string) {
		lbs, _, _ := e.fake.Snapshot()
		return len(lbs) == 1, "no balancer"
	})
	e.fake.Fail = errors.New("the cloud is down")
	e.must(e.c.Delete(e.ctx, "Silo", "d", "x"))
	for {
		if o, ok := e.ctl.Silos.Get("d", "x"); ok && o.(*v1.Silo).DeletionTimestamp != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := e.ctl.Reconcile(e.ctx, engine.Key{Kind: "Silo", Namespace: "d", Name: "x"}); err == nil {
		t.Fatal("removing the balancer failed, yet no error")
	}
	if cur, ok := e.get("x"); !ok || !strings.Contains(lbCond(cur.Status.Conditions), "the cloud is down") {
		t.Fatalf("the silo should stay, saying why: %v", ok)
	}
	e.fake.Fail = nil
	e.reconcile("Silo", "x", func() (bool, string) { _, ok := e.get("x"); return !ok, "still there" })
}

// A standalone Service of type LoadBalancer: backends are the hosts of its routed endpoints on
// the provider's machines, on its node ports; removed with the Service.
func TestServiceBalancer(t *testing.T) {
	e := newLBEnv(t)
	e.fake.BalancerIPv6 = true // its IPv6 goes on the Service's status too
	svc := &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "group", Namespace: "d"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "g"}, Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "fake"},
			Ports: []v1.ServicePortSpec{{Name: "web", Port: 443, TargetPort: "web"}}}}
	e.must(e.c.Create(e.ctx, svc))
	e.reconcile("Service", "group", func() (bool, string) {
		var cur v1.Service
		e.must(e.c.Get(e.ctx, "Service", "d", "group", &cur))
		c := meta.FindCondition(cur.Status.Conditions, "LoadBalancer")
		return c != nil && c.Reason == "Pending", lbCond(cur.Status.Conditions)
	})
	// Its endpoints and node ports, as the service controller writes them.
	var cur v1.Service
	e.must(e.c.Get(e.ctx, "Service", "d", "group", &cur))
	cur.Status.NodePorts = []v1.NodePort{{Name: "web", Port: 443, NodePort: 30100}}
	cur.Status.Endpoints = []v1.ServiceEndpoint{{Silo: "g-0", Host: "w1", SiloIP: "10.64.0.1"}, {Silo: "g-1", Host: "w2", SiloIP: "10.64.0.2"}, {Silo: "g-2", Host: "home", SiloIP: "10.64.0.3"}}
	e.must(e.c.UpdateStatus(e.ctx, &cur))
	e.reconcile("Service", "group", func() (bool, string) {
		var cur v1.Service
		e.must(e.c.Get(e.ctx, "Service", "d", "group", &cur))
		return cur.Status.LoadBalancerIP != "" && meta.IsTrue(cur.Status.Conditions, "LoadBalancer"), lbCond(cur.Status.Conditions)
	})
	e.must(e.c.Get(e.ctx, "Service", "d", "group", &cur))
	if want := e.fake.LBAddr6(cur.Status.LoadBalancerIP); cur.Status.LoadBalancerIPv6 != want || want == "" {
		t.Errorf("IPv6 %q, want the balancer's %q beside its IPv4", cur.Status.LoadBalancerIPv6, want)
	}
	lbs, _, _ := e.fake.Snapshot()
	lb := lbs[svc.UID]
	if len(lb.Backends) != 2 || lb.Backends[0].Name != "w1" || lb.Backends[1].Name != "w2" || lb.Ports[0].NodePort != 30100 {
		t.Errorf("balancer %+v: want w1 and w2 (home isn't the provider's) on node port 30100", lb)
	}
	e.must(e.c.Get(e.ctx, "Service", "d", "group", &cur))
	if !strings.Contains(lbCond(cur.Status.Conditions), "home") {
		t.Errorf("condition should name the endpoint it can't reach: %s", lbCond(cur.Status.Conditions))
	}
	e.must(e.c.Delete(e.ctx, "Service", "d", "group"))
	e.reconcile("Service", "group", func() (bool, string) {
		err := e.c.Get(e.ctx, "Service", "d", "group", &cur)
		return client.IsNotFound(err), fmt.Sprint(cur.Finalizers)
	})
	if lbs, _, _ := e.fake.Snapshot(); len(lbs) != 0 {
		t.Errorf("balancers left after the Service: %+v", lbs)
	}
}

var _ = kplugin.ErrNotFound
