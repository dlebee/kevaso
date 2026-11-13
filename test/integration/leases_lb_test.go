package integration

import (
	"context"
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
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", Address: "127.0.0.1",
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
		Spec: v1.HostSpec{Address: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
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
		Spec: v1.SiloSpec{Runtime: "docker", Image: "nginx", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, Ports: []v1.ServicePort{{Name: "web", Port: 80}, {Name: "debug", Port: 9229}},
				LoadBalancer: &v1.LoadBalancerSpec{Class: "fake-lb"}, Lease: &v1.ServiceLease{Ports: []string{"debug"}}}}}
	if err := admin.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	ports := func() []string {
		var cur v1.Silo
		_ = admin.Get(ctx, "Silo", "dev", "app", &cur)
		lbs, _, _ := fake.Snapshot()
		var out []string
		for _, p := range lbs[cur.UID].Ports {
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
	eventually("debug added while its lease is open", func() (bool, string) {
		p := ports()
		return slices.Equal(p, []string{"web", "debug"}), "ports " + strings.Join(p, ",")
	})
	eventually("debug gone at the lease's end", func() (bool, string) {
		p := ports()
		return slices.Equal(p, []string{"web"}) && !time.Now().Before(*ans.Lease.Status.Until), "ports " + strings.Join(p, ",")
	})
}
