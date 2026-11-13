package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

// Example 07 in a real control plane (M12): an Image, a SiloSet of three instances from it spread
// over two hosts, and a Service of type LoadBalancer in front of them through a plugin's class.
// Then a rolling upgrade to v2 (never more than one instance down), admission refusing what would
// run two copies, a scale-in that spares a protected instance, and deleting the set deleting its
// instances. The hosts' agents are played by this test: they report each placed instance running
// what it was given, after a moment.
func TestSiloSetAndService(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvs")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "1", Region: "ca-central", PrivateAddress: "192.168.130.5"}
	fake.Machines["203.0.113.6"] = kplugin.HostInfo{ID: "2", Region: "ca-central", PrivateAddress: "192.168.130.6"}
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
	hostAddr := map[string]string{"w1": "203.0.113.5", "w2": "203.0.113.6"}
	for name, addr := range hostAddr {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{Address: addr, Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		if err := admin.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	// The hosts: heartbeats, and their agents running whatever is placed on them.
	var mu sync.Mutex
	pending := map[string]time.Time{} // silo uid+generation → when its agent started on it
	maxDown := 0
	go func() {
		addr := 1
		addrs := map[string]string{}
		for ctx.Err() == nil {
			now := time.Now().UTC().Truncate(time.Second)
			for name := range hostAddr {
				var h v1.Host
				if admin.Get(ctx, "Host", "", name, &h) == nil {
					meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
					h.Status.LastHeartbeat = &now
					h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
					h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
					_ = admin.UpdateStatus(ctx, &h)
				}
			}
			list, err := admin.List(ctx, "Silo", "web3")
			if err == nil {
				down := 0
				for _, item := range list.Items {
					o, _, _ := v1.Decode(item)
					s := o.(*v1.Silo)
					if s.Status.Host == "" || s.Status.Image == nil || s.DeletionTimestamp != nil {
						continue
					}
					ready := meta.FindCondition(s.Status.Conditions, "Ready")
					done := s.Status.Image.Running == s.Status.Image.Ref && s.Status.Image.Reset == s.Spec.Reset &&
						ready != nil && ready.Status == meta.ConditionTrue && ready.ObservedGeneration == s.Generation
					if done {
						continue
					}
					if s.Labels[v1.LabelStandby] != "true" {
						down++
					}
					key := fmt.Sprintf("%s/%d", s.UID, s.Generation)
					mu.Lock()
					started, ok := pending[key]
					if !ok {
						pending[key] = time.Now()
					}
					mu.Unlock()
					if !ok || time.Since(started) < 300*time.Millisecond {
						continue // the agent is resetting it
					}
					if addrs[s.UID] == "" {
						addrs[s.UID] = fmt.Sprintf("10.64.%d.%d", map[string]int{"w1": 1, "w2": 2}[s.Status.Host], 1+addr)
						addr++
					}
					s.Status.Phase, s.Status.Address = "Running", addrs[s.UID]
					s.Status.Image.Running, s.Status.Image.Reset = s.Status.Image.Ref, s.Spec.Reset
					meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Running", ObservedGeneration: s.Generation}, now)
					_ = admin.UpdateStatus(ctx, s)
				}
				mu.Lock()
				maxDown = max(maxDown, down)
				mu.Unlock()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	// Both hosts Ready with docker first: spread is a preference, and a placed silo never moves.
	eventually("both hosts Ready", func() (bool, string) {
		ok := true
		for name := range hostAddr {
			var h v1.Host
			_ = admin.Get(ctx, "Host", "", name, &h)
			ok = ok && meta.IsTrue(h.Status.Conditions, "Ready") && h.Status.Runtimes["docker"].State == "Ready" && h.Status.Provider != nil
		}
		return ok, ""
	})
	if err := admin.Create(ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	// A set of containers: its image is a registry reference, and it rolls when that changes. (Images
	// are machine disks, for cloud-hypervisor: a version can't change once added.)
	sum := strings.Repeat("ab", 32)
	img := &v1.Image{TypeMeta: tm("Image"), ObjectMeta: meta.ObjectMeta{Name: "geth-disk", Namespace: "web3"},
		Spec: v1.ImageSpec{Versions: []v1.ImageVersion{{Name: "v1", Disk: &v1.ImageDisk{URL: "https://images.example.com/geth-1.img", SHA256: sum}}}}}
	if err := admin.Create(ctx, img); err != nil {
		t.Fatal(err)
	}
	set := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "rpc-pool", Namespace: "web3"},
		Spec: v1.SiloSetSpec{Image: "docker.io/ethereum/client-go:v1.14.0", Instances: 3, Spread: "host", UpgradePolicy: v1.UpgradeRolling,
			Template: v1.SiloTemplate{Labels: map[string]string{"app": "rpc"}, SiloSpec: v1.SiloSpec{Runtime: "docker",
				Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Service:   &v1.SiloService{Ports: []v1.ServicePort{{Name: "rpc", Port: 8545}}}}}}}
	if err := admin.Create(ctx, set); err != nil {
		t.Fatal(err)
	}
	svc := &v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3"},
		Spec: v1.ServiceSpec{Selector: map[string]string{"app": "rpc"}, Type: v1.ServiceLoadBalancer, LoadBalancerClass: "fake-lb",
			Ports: []v1.ServicePortSpec{{Name: "rpc", Port: 8545, TargetPort: "rpc"}}}}
	if err := admin.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	instances := func() []*v1.Silo {
		list, err := admin.List(ctx, "Silo", "web3")
		if err != nil {
			return nil
		}
		var out []*v1.Silo
		for _, item := range list.Items {
			o, _, _ := v1.Decode(item)
			if s := o.(*v1.Silo); s.Labels[v1.LabelSiloSet] == "rpc-pool" {
				out = append(out, s)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out
	}
	describe := func(l []*v1.Silo) string {
		var parts []string
		for _, s := range l {
			im := ""
			if s.Status.Image != nil {
				im = s.Status.Image.Running
			}
			parts = append(parts, s.Name+"@"+s.Status.Host+":"+im+":"+condMsgs(s.Status.Conditions))
		}
		return strings.Join(parts, " | ")
	}
	eventually("three instances running the image's v1, spread over both hosts", func() (bool, string) {
		l := instances()
		hosts := map[string]int{}
		ok := len(l) == 3
		for _, s := range l {
			hosts[s.Status.Host]++
			ok = ok && s.Status.Image != nil && s.Status.Image.Running == "docker.io/ethereum/client-go:v1.14.0" && meta.IsTrue(s.Status.Conditions, "Ready")
		}
		return ok && hosts["w1"] >= 1 && hosts["w2"] >= 1, describe(l)
	})
	if l := instances(); l[0].Name != "rpc-pool-0" || l[2].Name != "rpc-pool-2" {
		t.Fatalf("names: %s", describe(l))
	}
	eventually("the service: a virtual IP, three endpoints, a load balancer on both hosts", func() (bool, string) {
		var s v1.Service
		_ = admin.Get(ctx, "Service", "web3", "rpc", &s)
		lb, ok := fake.LBOf("web3", "service/rpc")
		return s.Status.ClusterIP == "10.65.0.1" && len(s.Status.Endpoints) == 3 && len(s.Status.NodePorts) == 1 &&
				s.Status.NodePorts[0].NodePort == v1.NodePortSiloMax+1 && s.Status.PublicIP != "" && ok && len(lb.Backends) == 2 &&
				lb.Ports[0].NodePort == v1.NodePortSiloMax+1,
			fmt.Sprintf("%+v lb=%+v", s.Status, lb)
	})
	var set1 v1.SiloSet
	eventually("the set Ready", func() (bool, string) {
		_ = admin.Get(ctx, "SiloSet", "web3", "rpc-pool", &set1)
		return set1.Status.Ready == 3 && set1.Status.Updated == 3 && meta.IsTrue(set1.Status.Conditions, "Ready"), condMsgs(set1.Status.Conditions)
	})

	// Admission: what would run two copies, or change an image under its instances, is refused.
	bad := *set
	bad.ObjectMeta = meta.ObjectMeta{Name: "validators", Namespace: "web3"}
	bad.Spec.Template.Exclusive, bad.Spec.Update = true, v1.SiloSetUpdate{Strategy: v1.StartFirst}
	if err := admin.Create(ctx, &bad); !client.IsInvalid(err) || !strings.Contains(err.Error(), "never two copies") {
		t.Fatalf("exclusive + StartFirst: %v", err)
	}
	bad.Spec.Update = v1.SiloSetUpdate{}
	bad.Spec.Template.Availability.OnHostLoss = v1.OnHostLossRecreate
	if err := admin.Create(ctx, &bad); !client.IsInvalid(err) || !strings.Contains(err.Error(), "template: exclusive: true forbids automatic failover") {
		t.Fatalf("exclusive + Recreate in a template: %v", err)
	}
	one := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "one", Namespace: "web3"},
		Spec: v1.SiloSpec{Runtime: "docker", Update: &v1.UpdatePolicy{Strategy: v1.StartFirst}}}
	if err := admin.Create(ctx, one); !client.IsInvalid(err) || !strings.Contains(err.Error(), "M14") {
		t.Fatalf("StartFirst on one silo: %v", err)
	}
	_ = admin.Get(ctx, "Image", "web3", "geth-disk", img)
	img.Spec.Versions[0].Disk.URL = "https://images.example.com/geth-1b.img"
	if err := admin.Update(ctx, img); !client.IsInvalid(err) || !strings.Contains(err.Error(), "can't change once added") {
		t.Fatalf("changing a version: %v", err)
	}
	wrong := *set
	wrong.ObjectMeta = meta.ObjectMeta{Name: "from-a-disk", Namespace: "web3"}
	wrong.Spec.Image = "geth-disk:v1"
	if err := admin.Create(ctx, &wrong); !client.IsInvalid(err) || !strings.Contains(err.Error(), "geth-disk is an Image, a disk image for cloud-hypervisor") {
		t.Fatalf("a set of containers from an Image: %v", err)
	}

	// v2, rolled out by changing the reference: one instance down at a time, the service following.
	mu.Lock()
	maxDown = 0
	mu.Unlock()
	_ = admin.Get(ctx, "SiloSet", "web3", "rpc-pool", set)
	set.Spec.Image = "docker.io/ethereum/client-go:v1.15.0"
	if err := admin.Update(ctx, set); err != nil {
		t.Fatal(err)
	}
	eventually("every instance on v2", func() (bool, string) {
		l := instances()
		ok := len(l) == 3
		for _, s := range l {
			ok = ok && s.Status.Image != nil && s.Status.Image.Running == "docker.io/ethereum/client-go:v1.15.0" && meta.IsTrue(s.Status.Conditions, "Ready")
		}
		var st v1.SiloSet
		_ = admin.Get(ctx, "SiloSet", "web3", "rpc-pool", &st)
		return ok && st.Status.Updated == 3 && st.Status.Ready == 3, describe(l)
	})
	mu.Lock()
	if maxDown > 1 {
		t.Errorf("%d instances were down at once during the rollout (maxUnavailable 1)", maxDown)
	}
	mu.Unlock()
	eventually("the service back to three endpoints", func() (bool, string) {
		var s v1.Service
		_ = admin.Get(ctx, "Service", "web3", "rpc", &s)
		return len(s.Status.Endpoints) == 3, fmt.Sprint(s.Status.Endpoints)
	})

	// Scale in to one, with rpc-pool-1 protected: rpc-pool-0 and rpc-pool-2 go.
	p := instances()[1]
	p.Labels[v1.LabelProtected] = "true"
	if err := admin.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	_ = admin.Get(ctx, "SiloSet", "web3", "rpc-pool", set)
	set.Spec.Instances = 1
	if err := admin.Update(ctx, set); err != nil {
		t.Fatal(err)
	}
	eventually("only the protected one left", func() (bool, string) {
		l := instances()
		return len(l) == 1 && l[0].Name == "rpc-pool-1", describe(l)
	})
	eventually("the load balancer down to its host", func() (bool, string) {
		var s v1.Service
		_ = admin.Get(ctx, "Service", "web3", "rpc", &s)
		lb, _ := fake.LBOf("web3", "service/rpc")
		return len(s.Status.Endpoints) == 1 && len(lb.Backends) == 1, fmt.Sprintf("%+v", lb)
	})

	// Deleting the set deletes its instances; deleting the service, its load balancer.
	if err := admin.Delete(ctx, "SiloSet", "web3", "rpc-pool"); err != nil {
		t.Fatal(err)
	}
	if err := admin.Delete(ctx, "Service", "web3", "rpc"); err != nil {
		t.Fatal(err)
	}
	eventually("set, instances, service and load balancer gone", func() (bool, string) {
		var st v1.SiloSet
		setErr := admin.Get(ctx, "SiloSet", "web3", "rpc-pool", &st)
		var s v1.Service
		svcErr := admin.Get(ctx, "Service", "web3", "rpc", &s)
		lbs, _, _ := fake.Snapshot()
		return client.IsNotFound(setErr) && client.IsNotFound(svcErr) && len(instances()) == 0 && len(lbs) == 0,
			fmt.Sprintf("set=%v svc=%v instances=%s lbs=%d", setErr, svcErr, describe(instances()), len(lbs))
	})
}
