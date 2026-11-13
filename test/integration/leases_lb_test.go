package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kplugin/kplugintest"
)

// Design §7.2d on a plugin's load balancer, in a real control plane: a closed leased port has no
// backend port; opening it adds it; at the lease's end it goes again without anything else
// changing.
func TestPortLeaseOnPluginLoadBalancer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvq")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "42", Region: "ca-central", PrivateAddress: "192.168.130.5"}
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		Plugins: reg}); err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	eventually := func(what string, cond func() (bool, string)) {
		t.Helper()
		last := ""
		for ctx.Err() == nil {
			ok, s := cond()
			if ok {
				return
			}
			last = s
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: never happened; last: %s", what, last)
	}
	ready := func(h *v1.Host) {
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	}
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
	if err := admin.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	ready(h)
	if err := admin.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	go func() { // the worker's heartbeat
		for ctx.Err() == nil {
			var h v1.Host
			if admin.Get(ctx, "Host", "", "w1", &h) == nil {
				ready(&h)
				_ = admin.UpdateStatus(ctx, &h)
			}
			time.Sleep(time.Second)
		}
	}()
	if err := admin.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "app", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Ports: []v1.SiloPort{{Name: "web", Port: 80}, {Name: "debug", Port: 9229}, {Name: "preview", Port: 3000}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "web", LoadBalancer: true},
				{Port: "debug", LoadBalancer: true, Lease: &v1.PortLease{}}, {Port: "preview", LoadBalancer: true, Lease: &v1.PortLease{Max: "2h"}}},
				LoadBalancer: &v1.LoadBalancerSpec{Class: "fake-lb"}}}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	ports := func() []string {
		var cur v1.Silo
		_ = admin.Get(ctx, "Silo", "dev", "app", &cur)
		lb, _ := fake.LBOf("dev", "silo/app")
		var out []string
		for _, p := range lb.Ports {
			out = append(out, p.Name)
		}
		return out
	}
	eventually("a load balancer with web only", func() (bool, string) {
		p := ports()
		return slices.Equal(p, []string{"web"}), "ports " + strings.Join(p, ",")
	})
	var ans client.LeaseAnswer
	if err := admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/app/open", v1.LeaseOpenRequest{Port: "debug", For: "3s"}, &ans); err != nil {
		t.Fatal(err)
	}
	eventually("debug added while its lease is open (preview still closed)", func() (bool, string) {
		p := ports()
		return slices.Equal(p, []string{"web", "debug"}), "ports " + strings.Join(p, ",")
	})
	if err := admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/app/open", v1.LeaseOpenRequest{Port: "preview", For: "1h"}, nil); err != nil {
		t.Fatal(err)
	}
	eventually("debug gone at its lease's end, preview open on its own clock", func() (bool, string) {
		p := ports()
		return slices.Equal(p, []string{"web", "preview"}) && !time.Now().Before(*ans.Lease.Status.Until), "ports " + strings.Join(p, ",")
	})
}

// Design §7.2d: a leased port opens only to its own sources (each port its own).
// A node-port load balancer is where client addresses can still be checked (the host sees only the
// load balancer's), so the sources go to the plugin per port; a class that can't filter them gets
// no port it would open wider: it's left out, and the silo says why.
func TestLeaseSourcesOnPluginLoadBalancer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvq")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "42", Region: "ca-central", PrivateAddress: "192.168.130.5"}
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		Plugins: reg}); err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	eventually := func(what string, cond func() (bool, string)) {
		t.Helper()
		last := ""
		for ctx.Err() == nil {
			ok, s := cond()
			if ok {
				return
			}
			last = s
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: never happened; last: %s", what, last)
	}
	ready := func(h *v1.Host) {
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	}
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
	if err := admin.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	ready(h)
	if err := admin.UpdateStatus(ctx, h); err != nil {
		t.Fatal(err)
	}
	go func() {
		for ctx.Err() == nil {
			var h v1.Host
			if admin.Get(ctx, "Host", "", "w1", &h) == nil {
				ready(&h)
				_ = admin.UpdateStatus(ctx, &h)
			}
			time.Sleep(time.Second)
		}
	}()
	if err := admin.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	silo := func(name, class string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports: []v1.SiloPort{{Name: "web", Port: 80}, {Name: "debug", Port: 9229}, {Name: "metrics", Port: 9100}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "web", LoadBalancer: true, Sources: []string{"203.0.113.0/24"}},
					{Port: "debug", LoadBalancer: true, Sources: []string{"203.0.113.7"}, Lease: &v1.PortLease{}},
					{Port: "metrics", LoadBalancer: true, Sources: []string{"203.0.113.64/26"}, Lease: &v1.PortLease{}}},
					LoadBalancer: &v1.LoadBalancerSpec{Class: class}}}}
	}
	for _, s := range []*v1.Silo{silo("filtered", kplugintest.ClassFilteredLB), silo("plain", "fake-lb")} {
		if err := admin.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	ports := func(name string) (map[string][]string, v1.Silo) {
		var cur v1.Silo
		_ = admin.Get(ctx, "Silo", "dev", name, &cur)
		lb, ok := fake.LBOf("dev", "silo/"+name)
		if !ok {
			return nil, cur
		}
		out := map[string][]string{}
		for _, p := range lb.Ports {
			out[p.Name] = p.Sources
		}
		return out, cur
	}
	show := func(m map[string][]string) string { return fmt.Sprint(m) }
	eventually("filtered: web with its sources", func() (bool, string) {
		p, _ := ports("filtered")
		_, debug := p["debug"]
		return slices.Equal(p["web"], []string{"203.0.113.0/24"}) && !debug, show(p)
	})
	eventually("plain: nothing it can't limit", func() (bool, string) {
		p, cur := ports("plain")
		c := meta.FindCondition(cur.Status.Conditions, "LoadBalancer")
		ok := len(p) == 0 && c != nil && c.Reason == "SourcesNotEnforced" && strings.Contains(c.Message, "web") // no port on its IP's balancer
		msg := ""
		if c != nil {
			msg = c.Reason + ": " + c.Message
		}
		return ok, show(p) + " " + msg
	})
	for _, name := range []string{"filtered", "plain"} {
		for _, port := range []string{"debug", "metrics"} {
			if err := admin.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/"+name+"/open", v1.LeaseOpenRequest{Port: port, For: "1h"}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	eventually("filtered: each leased port open to its own sources", func() (bool, string) {
		p, _ := ports("filtered")
		return slices.Equal(p["debug"], []string{"203.0.113.7"}) && slices.Equal(p["metrics"], []string{"203.0.113.64/26"}) &&
			slices.Equal(p["web"], []string{"203.0.113.0/24"}), show(p)
	})
	eventually("plain: the open lease adds nothing", func() (bool, string) {
		p, cur := ports("plain")
		c := meta.FindCondition(cur.Status.Conditions, "LoadBalancer")
		return len(p) == 0 && c != nil && c.Reason == "SourcesNotEnforced" && strings.Contains(c.Message, "debug"), show(p)
	})
}
