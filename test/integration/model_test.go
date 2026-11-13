package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/names"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/worker"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// modelRig is a control plane with three workers, the design's mixed cluster (§7.0, "three ways
// in"): a cloud VM with an internal and an external IP, a LAN host behind a balancer the fake
// plugin provides (its internal IP is the plugin's machine), and a LAN host with only an internal
// IP. There's no agent: silos get their silo IPs from the test, as an agent would report them.
type modelRig struct {
	t     *testing.T
	ctx   context.Context
	admin *client.Client
}

func newModelRig(t *testing.T) *modelRig {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	dir, _ := os.MkdirTemp("/tmp", "kvmd")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["192.168.130.5"] = kplugin.HostInfo{ID: "7", Region: "ca-central", PrivateAddress: "192.168.130.5"}
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		Plugins: reg}); err != nil {
		t.Fatal(err)
	}
	r := &modelRig{t: t, ctx: ctx, admin: client.NewUnix(filepath.Join(dir, "a.sock"))}
	for _, h := range []struct{ name, internal, external, site string }{
		{"ext-1", "10.0.0.11", "51.38.10.21", "cloud"},
		{"lb-1", "192.168.130.5", "", "lb"},
		{"lan-1", "192.168.1.20", "", "lan"},
	} {
		if err := r.admin.Create(ctx, &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: h.name},
			Spec: v1.HostSpec{InternalIP: h.internal, ExternalIP: h.external,
				Components: v1.HostComponents{Worker: &v1.WorkerSpec{Labels: map[string]string{"site": h.site}, Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	go func() { // the workers' heartbeats
		for ctx.Err() == nil {
			for _, n := range []string{"ext-1", "lb-1", "lan-1"} {
				var h v1.Host
				if r.admin.Get(ctx, "Host", "", n, &h) == nil {
					now := time.Now().UTC().Truncate(time.Second)
					meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
					h.Status.LastHeartbeat = &now
					h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
					h.Status.Allocatable = v1.Resources{CPU: 16, Memory: "32Gi"}
					_ = r.admin.UpdateStatus(ctx, &h)
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	r.eventually("lb-1 recognised as the plugin's, by its internal IP", func() (bool, string) {
		var h v1.Host
		_ = r.admin.Get(ctx, "Host", "", "lb-1", &h)
		return h.Status.Provider != nil && h.Status.Provider.ID == "7", fmt.Sprintf("%+v", h.Status.Provider)
	})
	if err := r.admin.Create(ctx, ns("shop")); err != nil {
		t.Fatal(err)
	}
	return r
}

func tm(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func (r *modelRig) eventually(what string, cond func() (bool, string)) {
	r.t.Helper()
	last := ""
	for r.ctx.Err() == nil {
		ok, s := cond()
		if ok {
			return
		}
		last = s
		time.Sleep(50 * time.Millisecond)
	}
	r.t.Fatalf("%s: never happened; last: %s", what, last)
}

func (r *modelRig) silo(name string) *v1.Silo {
	var s v1.Silo
	_ = r.admin.Get(r.ctx, "Silo", "shop", name, &s)
	return &s
}

// running waits for the silo to be placed, then gives it a silo IP, as its host's agent would.
func (r *modelRig) running(name, ip string) *v1.Silo {
	r.t.Helper()
	r.eventually(name+" placed", func() (bool, string) {
		s := r.silo(name)
		return s.Status.Host != "", fmt.Sprintf("%+v", s.Status.Conditions)
	})
	for i := 0; ; i++ {
		s := r.silo(name)
		s.Status.Phase, s.Status.SiloIP = "Running", ip
		err := r.admin.UpdateStatus(r.ctx, s)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || i > 20 {
			r.t.Fatal(err)
		}
	}
	return r.silo(name)
}

func (r *modelRig) all() ([]*v1.Silo, []*v1.Host, []*v1.Service) {
	var silos []*v1.Silo
	var hosts []*v1.Host
	var svcs []*v1.Service
	for kind, add := range map[string]func(meta.Object){
		"Silo":    func(o meta.Object) { silos = append(silos, o.(*v1.Silo)) },
		"Host":    func(o meta.Object) { hosts = append(hosts, o.(*v1.Host)) },
		"Service": func(o meta.Object) { svcs = append(svcs, o.(*v1.Service)) },
	} {
		l, err := r.admin.List(r.ctx, kind, "")
		if err != nil {
			r.t.Fatal(err)
		}
		for _, raw := range l.Items {
			if o, _, err := v1.Decode(raw); err == nil {
				add(o)
			}
		}
	}
	return silos, hosts, svcs
}

// rules is the firewall host would write now.
func (r *modelRig) rules(host string) string {
	silos, hosts, svcs := r.all()
	var me *v1.Host
	for _, h := range hosts {
		if h.Name == host {
			me = h
		}
	}
	view := worker.NetworkView(host, me, silos, nil, nil)
	view.Services = worker.ServiceView(host, svcs)
	return kni.Rules(view)
}

func set(name, port string, number int, nets []string, site string) *v1.SiloSet {
	return &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "shop"},
		Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{Labels: map[string]string{"app": name},
			SiloSpec: v1.SiloSpec{Runtime: "docker", Image: "docker.io/library/nginx:1.27", Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Placement: v1.Placement{HostSelector: map[string]string{"site": site}},
				Ports:     []v1.SiloPort{{Name: port, Port: number}},
				Service:   &v1.SiloService{Ports: []v1.ServicePort{{Port: port, HostPort: nets, As: 443}}}}}}}
}

// The three ways in (design §7.0): one api silo that opens nothing on any host, reached by three
// sets of proxies: on hosts with their own external IP (hostPort: [external]); on a LAN host
// behind a balancer that holds the external IP (hostPort: [internal], the balancer from the fake
// plugin in front); internal only (hostPort: [internal], nothing in front). The second and third
// are written the same way; what sits in front is the network's business.
func TestThreeWaysIn(t *testing.T) {
	r := newModelRig(t)
	api := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "api-blue", Namespace: "shop"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "docker.io/library/nginx:1.27", Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Placement: v1.Placement{HostSelector: map[string]string{"site": "lan"}},
			Ports:     []v1.SiloPort{{Name: "http", Port: 8080}},
			Service: &v1.SiloService{Name: "api", Ports: []v1.ServicePort{
				{Port: "http", AllowFrom: []string{"edge-0", "front-0", "inside-0"}}}}}}
	for _, o := range []meta.Object{api,
		set("edge", "https", 8443, []string{"external"}, "cloud"),
		set("front", "https", 8443, []string{"internal"}, "lb"),
		set("inside", "https", 8443, []string{"internal"}, "lan"),
		&v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "front-lb", Namespace: "shop"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": "front"}, Type: v1.ServiceLoadBalancer, LoadBalancerClass: kplugintest.ClassLB,
				Ports: []v1.ServicePortSpec{{Name: "https", Port: 443}}}},
	} {
		if err := r.admin.Create(r.ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	apiS := r.running("api-blue", "10.64.3.2")
	edge := r.running("edge-0", "10.64.1.2")
	front := r.running("front-0", "10.64.2.2")
	inside := r.running("inside-0", "10.64.3.3")
	for s, host := range map[*v1.Silo]string{edge: "ext-1", front: "lb-1", inside: "lan-1", apiS: "lan-1"} {
		if s.Status.Host != host {
			t.Errorf("%s on %s, want %s", s.Name, s.Status.Host, host)
		}
	}
	// Where each is reachable, in its status.
	r.eventually("ports in status", func() (bool, string) {
		e, f, a := r.silo("edge-0"), r.silo("front-0"), r.silo("api-blue")
		ok := len(e.Status.Service.Ports) == 1 && e.Status.Service.Ports[0].External == "51.38.10.21:443" && e.Status.Service.Ports[0].Internal == "" &&
			len(f.Status.Service.Ports) == 1 && f.Status.Service.Ports[0].Internal == "192.168.130.5:443" &&
			len(a.Status.Service.Ports) == 1 && a.Status.Service.Ports[0].Mesh == "10.64.3.2:8080" && len(a.Status.Service.OutsideIPs()) == 0 &&
			a.Status.Service.Name == "api.shop.kevaso"
		return ok, fmt.Sprintf("edge %+v front %+v api %+v", e.Status.Service, f.Status.Service, a.Status.Service)
	})
	// The firewall: each proxy's port on exactly its address; api on none, open to the three
	// proxies on its silo IP only.
	ext, lb, lan := r.rules("ext-1"), r.rules("lb-1"), r.rules("lan-1")
	for _, c := range []struct {
		rules, want string
	}{
		{ext, "ip daddr 51.38.10.21 tcp dport 443 dnat ip to 10.64.1.2:8443"},
		{lb, "ip daddr 192.168.130.5 tcp dport 443 dnat ip to 10.64.2.2:8443"},
		{lan, "ip daddr 192.168.1.20 tcp dport 443 dnat ip to 10.64.3.3:8443"},
		{lan, `oifname "kvbr0" ip saddr 10.64.1.2 ip daddr 10.64.3.2 tcp dport 8080 accept`},
		{lan, `oifname "kvbr0" ip saddr 10.64.2.2 ip daddr 10.64.3.2 tcp dport 8080 accept`},
		{lan, `ip saddr 10.64.3.3 ip daddr 10.64.3.2 tcp dport 8080 accept`},
	} {
		if !strings.Contains(c.rules, c.want) {
			t.Errorf("missing %q", c.want)
		}
	}
	for _, rs := range []string{ext, lb, lan} {
		if strings.Contains(rs, "dnat ip to 10.64.3.2") || strings.Contains(rs, "ip daddr 10.0.0.11 tcp dport 443") {
			t.Errorf("api, or edge's internal IP, opened on a host:\n%s", rs)
		}
	}
	// The balancer in front of the LAN proxies: an address from the fake plugin.
	r.eventually("front-lb's address", func() (bool, string) {
		var svc v1.Service
		_ = r.admin.Get(r.ctx, "Service", "shop", "front-lb", &svc)
		return svc.Status.LoadBalancerIP != "" && len(svc.Status.Endpoints) == 1, fmt.Sprintf("%+v", svc.Status)
	})
	// Names, by who asks.
	silos, hosts, svcs := r.all()
	view := names.View{Silos: silos, Services: svcs, Hosts: hosts}
	for _, c := range []struct {
		name string
		from names.Asker
		want string
	}{
		{"api.shop.kevaso", names.FromSilo, "10.64.3.2"},
		{"api", names.FromSilo, "10.64.3.2"},
		{"api.shop.kevaso", names.FromOutside, ""},
		{"api.shop.kevaso", names.FromNetwork, ""},
		{"edge-0.shop.kevaso", names.FromOutside, "51.38.10.21"},
		{"edge-0.shop.kevaso", names.FromNetwork, "51.38.10.21"}, // no internal port: its external answer
		{"inside-0.shop.kevaso", names.FromNetwork, "192.168.1.20"},
		{"inside-0.shop.kevaso", names.FromOutside, ""},
		{"front-0.shop.internal.kevaso", names.FromHost, "192.168.130.5"},
		{"lan-1.internal.kevaso", names.FromNetwork, "192.168.1.20"},
		{"lan-1.external.kevaso", names.FromHost, ""},
	} {
		a := names.Resolve(names.Question{Name: c.name, From: c.from, Namespace: "shop"}, view)
		got := ""
		for _, ip := range a.IPs {
			got += ip.String()
		}
		if !a.Found || got != c.want {
			t.Errorf("%s asks %s: %q (%+v), want %q", c.from, c.name, got, a, c.want)
		}
	}
}

// What the model refuses, and says why: a port asking for an address no host has; two silos
// claiming one service name; a number on an address another silo holds.
func TestModelRefusals(t *testing.T) {
	r := newModelRig(t)
	mk := func(name, service string, nets []string, site string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "shop"},
			Spec: v1.SiloSpec{Runtime: "docker", Image: "docker.io/library/nginx:1.27", Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Placement: v1.Placement{HostSelector: map[string]string{"site": site}},
				Ports:     []v1.SiloPort{{Name: "https", Port: 8443}},
				Service:   &v1.SiloService{Name: service, Ports: []v1.ServicePort{{Port: "https", HostPort: nets, As: 443}}}}}
	}
	unschedulable := func(name, why string) {
		t.Helper()
		r.eventually(name+" unschedulable: "+why, func() (bool, string) {
			s := r.silo(name)
			c := meta.FindCondition(s.Status.Conditions, "Scheduled")
			return s.Status.Host == "" && c != nil && strings.Contains(c.Message, why), fmt.Sprintf("%+v", s.Status)
		})
	}
	// Only an internal IP there: an [external] port can't land.
	if err := r.admin.Create(r.ctx, mk("public", "", []string{"external"}, "lan")); err != nil {
		t.Fatal(err)
	}
	unschedulable("public", "lan-1: no external IP, which port 443/TCP asks for (hostPort: [external])")

	// One name, one owner.
	if err := r.admin.Create(r.ctx, mk("api-blue", "api", []string{"external"}, "cloud")); err != nil {
		t.Fatal(err)
	}
	err := r.admin.Create(r.ctx, mk("api-green", "api", []string{"internal"}, "cloud"))
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusConflict || !strings.Contains(err.Error(), "the service name api is silo/api-blue's") {
		t.Fatalf("a second silo named api: %v", err)
	}
	// A standalone Service can't take it either; nor a silo whose own name is it.
	err = r.admin.Create(r.ctx, &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "shop"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "x"}, Ports: []v1.ServicePortSpec{{Name: "https", Port: 443}}}})
	if err == nil || !strings.Contains(err.Error(), "silo/api-blue") {
		t.Fatalf("a Service named api: %v", err)
	}

	// The same address and number: the second goes nowhere, saying who holds it.
	r.running("api-blue", "10.64.1.2")
	if err := r.admin.Create(r.ctx, mk("other", "", []string{"external"}, "cloud")); err != nil {
		t.Fatal(err)
	}
	unschedulable("other", "ext-1: port 443/TCP on the external IP (51.38.10.21) is held by shop/api-blue")
	// On the internal IP, the same number is free.
	if err := r.admin.Create(r.ctx, mk("inner", "", []string{"internal"}, "cloud")); err != nil {
		t.Fatal(err)
	}
	r.eventually("inner placed on ext-1", func() (bool, string) {
		s := r.silo("inner")
		return s.Status.Host == "ext-1", fmt.Sprintf("%+v", s.Status.Conditions)
	})
	// A namespace can't be named after a network.
	if err := r.admin.Create(r.ctx, ns("external")); err == nil || !strings.Contains(err.Error(), "a network's name") {
		t.Fatalf("namespace external: %v", err)
	}
}
