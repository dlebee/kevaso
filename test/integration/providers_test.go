package integration

import (
	"context"
	"os"
	"path/filepath"
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

// A provider plugin in a real control plane (M11): its machines are recognised among the hosts; a
// silo on its load-balancer class and storage class lands on one of them, gets node ports, an
// address, and a volume created and attached; an IngressClass with DNS publishes its host names;
// and deleting the silo waits for the host to unmount the volume, detaches it (taking a while),
// deletes it and the load balancer, and only then lets the silo go.
func TestProviderPlugin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvp")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "42", Region: "ca-central", PrivateAddress: "192.168.130.5"}
	fake.DetachSlow = 2
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
	// Two workers: w1 is one of the plugin's machines, home isn't.
	for name, addr := range map[string]string{"w1": "203.0.113.5", "home": "198.51.100.9"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{Address: addr, Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}},
				Labels: map[string]string{"site": name}}}}}
		if err := admin.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
		if err := admin.UpdateStatus(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	go func() { // the workers' heartbeats
		for ctx.Err() == nil {
			for _, name := range []string{"w1", "home"} {
				var h v1.Host
				if admin.Get(ctx, "Host", "", name, &h) == nil {
					now := time.Now().UTC().Truncate(time.Second)
					meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
					h.Status.LastHeartbeat = &now
					_ = admin.UpdateStatus(ctx, &h)
				}
			}
			time.Sleep(time.Second)
		}
	}()
	eventually("w1 recognised as the plugin's", func() (bool, string) {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "w1", &h)
		return h.Status.Provider != nil && h.Status.Provider.ID == "42" && h.Status.Provider.Region == "ca-central", ""
	})
	var home v1.Host
	_ = admin.Get(ctx, "Host", "", "home", &home)
	if home.Status.Provider != nil {
		t.Fatalf("home isn't the plugin's: %+v", home.Status.Provider)
	}

	for _, n := range []string{"kevaso-system", "payments"} {
		if err := admin.Create(ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	db := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "payments"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "postgres:17", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, Ports: []v1.ServicePort{{Name: "pg", Port: 5432}},
				LoadBalancer: &v1.LoadBalancerSpec{Class: "fake-lb"}},
			Volumes: []v1.Volume{{Name: "data", Class: "fake-block", Size: "10Gi", MountPath: "/var/lib/postgresql/data"}}}}
	if err := admin.Create(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Scheduled on w1, not home; node port, address, volume attached.
	eventually("db placed with its load balancer and volume", func() (bool, string) {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "payments", "db", &s)
		ok := s.Status.Host == "w1" && s.Status.Service.PublicIP == "198.51.100.10" && len(s.Status.Service.NodePorts) == 1 &&
			s.Status.Service.NodePorts[0].NodePort == v1.NodePortMin && len(s.Status.Service.SourceRanges) == 1 &&
			len(s.Status.Volumes) == 1 && s.Status.Volumes[0].AttachedTo == "w1" && s.Status.Volumes[0].Device != "" &&
			s.Status.Volumes[0].Region == "ca-central"
		return ok, s.Status.Host + " " + s.Status.Service.PublicIP + " " + strings.Join(s.Finalizers, ",") + " " + condMsgs(s.Status.Conditions) + volMsgs(s.Status.Volumes)
	})
	var s v1.Silo
	_ = admin.Get(ctx, "Silo", "payments", "db", &s)
	if m := meta.FindCondition(s.Status.Conditions, "Scheduled"); m == nil || !strings.Contains(m.Message, "w1") {
		t.Fatalf("scheduled: %+v", m)
	}
	// Heartbeats and status writes don't reach the cloud: with nothing changed, three seconds of
	// heartbeats from both workers make no plugin calls.
	before := len(fake.CallLog())
	time.Sleep(3 * time.Second)
	if extra := fake.CallLog()[before:]; len(extra) > 0 {
		t.Fatalf("plugin called with nothing changed: %v", extra)
	}
	_, vols, _ := fake.Snapshot()
	if lb, _ := fake.LBOf("payments", "silo/db"); len(lb.Backends) != 1 || lb.Backends[0].ID != "42" || lb.Ports[0].NodePort != v1.NodePortMin {
		t.Fatalf("load balancer the plugin got: %+v", lb)
	}
	if len(vols) != 1 {
		t.Fatalf("volumes: %+v", vols)
	}

	// A silo on a class only the plugin's machines serve, held to home by a label: no host fits.
	stray := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "stray", Namespace: "payments"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "busybox", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Placement: v1.Placement{HostSelector: map[string]string{"site": "home"}},
			Volumes:   []v1.Volume{{Name: "x", Class: "fake-block", Size: "1Gi", MountPath: "/x"}}}}
	if err := admin.Create(ctx, stray); err != nil {
		t.Fatal(err)
	}
	eventually("stray unschedulable, saying why", func() (bool, string) {
		var x v1.Silo
		_ = admin.Get(ctx, "Silo", "payments", "stray", &x)
		c := meta.FindCondition(x.Status.Conditions, "Scheduled")
		return c != nil && c.Reason == "Unschedulable" && strings.Contains(c.Message, "home: class fake-block needs a fake machine"), condMsgs(x.Status.Conditions)
	})

	// Ingress host names published through the class's DNS provider, at the controller's address.
	ingress := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "ingress", Namespace: "kevaso-system"},
		Spec: v1.SiloSpec{Runtime: "docker", Image: "caddy", Resources: v1.Resources{CPU: 1, Memory: "512Mi"},
			Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, Ports: []v1.ServicePort{{Name: "https", Port: 443}},
				LoadBalancer: &v1.LoadBalancerSpec{Class: "fake-lb"}}}}
	if err := admin.Create(ctx, ingress); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "web"},
		Spec: v1.IngressClassSpec{Controller: v1.SiloRef{Silo: "ingress", Namespace: "kevaso-system"}, DNS: &v1.IngressDNS{Provider: "fake-dns", TTL: 120}}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: "shop", Namespace: "payments"},
		Spec: v1.IngressSpec{IngressClass: "web", Hosts: []string{"shop.example.com"}, TLS: v1.IngressTLS{Issuer: "internal-ca"},
			Rules: []v1.IngressRule{{Path: "/", Silo: v1.IngressTarget{Name: "db", Port: "pg"}}}}}); err != nil {
		t.Fatal(err)
	}
	var ctrlIP string
	eventually("shop.example.com published", func() (bool, string) {
		var x v1.Silo
		_ = admin.Get(ctx, "Silo", "kevaso-system", "ingress", &x)
		ctrlIP = x.Status.Service.PublicIP
		_, _, recs := fake.Snapshot()
		r, ok := recs["shop.example.com/A"]
		var ing v1.Ingress
		_ = admin.Get(ctx, "Ingress", "payments", "shop", &ing)
		return ok && ctrlOK(ctrlIP, r) && r.TTL == 120 && r.Owner == "kevaso:it/ingress/payments/shop" && len(ing.Status.DNSNames) == 1,
			ctrlIP + " " + condMsgs(ing.Status.Conditions)
	})
	if err := admin.Delete(ctx, "Ingress", "payments", "shop"); err != nil {
		t.Fatal(err)
	}
	eventually("the record goes with the Ingress", func() (bool, string) {
		_, _, recs := fake.Snapshot()
		var ing v1.Ingress
		err := admin.Get(ctx, "Ingress", "payments", "shop", &ing)
		return len(recs) == 0 && client.IsNotFound(err), ""
	})

	// The agent says it mounted the volume; then the silo is deleted.
	setMounted := func(m bool) {
		t.Helper()
		for i := 0; i < 10; i++ {
			var cur v1.Silo
			if err := admin.Get(ctx, "Silo", "payments", "db", &cur); err != nil {
				t.Fatal(err)
			}
			cur.Status.Volumes[0].Mounted = m
			if err := admin.UpdateStatus(ctx, &cur); err == nil {
				return
			}
		}
		t.Fatal("couldn't set mounted")
	}
	setMounted(true)
	if err := admin.Delete(ctx, "Silo", "payments", "db"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	var held v1.Silo
	if err := admin.Get(ctx, "Silo", "payments", "db", &held); err != nil {
		t.Fatalf("the silo went while its volume was still mounted: %v", err)
	}
	if !strings.Contains(volMsgs(held.Status.Volumes), "waiting for w1 to unmount it") {
		t.Fatalf("while mounted: %s", volMsgs(held.Status.Volumes))
	}
	setMounted(false) // the agent removed the container and unmounted
	eventually("volume detached (slowly) and deleted, silo gone, and the namespace's default IP (its last service gone) with its balancer", func() (bool, string) {
		_, vols, _ := fake.Snapshot()
		var x v1.Silo
		err := admin.Get(ctx, "Silo", "payments", "db", &x)
		_, there := fake.LBOf("payments", "silo/db")
		var ip v1.IP
		ipErr := admin.Get(ctx, "IP", "payments", v1.DefaultIPName("fake-lb"), &ip)
		return len(vols) == 0 && !there && client.IsNotFound(err) && client.IsNotFound(ipErr),
			volMsgs(x.Status.Volumes) + strings.Join(x.Finalizers, ",") + " ip " + ip.Status.Holders()
	})
	detaches := 0
	for _, c := range fake.CallLog() {
		if strings.HasPrefix(c, "detach ") {
			detaches++
		}
	}
	if detaches < 3 {
		t.Errorf("a slow detach is asked again until it's done: %d calls (%v)", detaches, fake.CallLog())
	}
}

func ctrlOK(ip string, r kplugin.Record) bool {
	return ip != "" && len(r.Values) == 1 && r.Values[0] == ip
}

func condMsgs(cs []meta.Condition) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Type+"="+string(c.Status)+" "+c.Reason+": "+c.Message)
	}
	return strings.Join(out, "; ")
}

func volMsgs(vs []v1.VolumeStatus) string {
	var out []string
	for _, v := range vs {
		out = append(out, v.Name+": "+v.Message)
	}
	return strings.Join(out, "; ")
}
