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

// IP objects in a real control plane with the fake plugin (design §7.2c-1, §7.2b): an IP made by
// hand is reserved before any service, a silo's service takes it, the silo goes and the address
// stays, a new silo takes the same address; a service naming no IP gets one that goes with it
// unless kept; a bound IP can't be deleted or taken; sameAsService behind a balancer is refused;
// ip-pool hands out a host's own addresses, which can't be taken from the host while in use.
func TestIPs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvip")
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
	for _, name := range []string{"w1"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{Address: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}},
				Network: v1.HostNetwork{Addresses: []string{"192.0.2.16/30"}}}}
		if err := admin.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	go func() { // the worker's heartbeat
		for ctx.Err() == nil {
			var h v1.Host
			if admin.Get(ctx, "Host", "", "w1", &h) == nil {
				now := time.Now().UTC().Truncate(time.Second)
				meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
				h.Status.LastHeartbeat = &now
				h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
				h.Status.Allocatable = v1.Resources{CPU: 16, Memory: "32Gi"}
				_ = admin.UpdateStatus(ctx, &h)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	eventually("w1 recognised as the plugin's", func() (bool, string) {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "w1", &h)
		return h.Status.Provider != nil && h.Status.Provider.Region == "ca-central" && meta.IsTrue(h.Status.Conditions, "Ready"), ""
	})
	if err := admin.Create(ctx, ns("web3")); err != nil {
		t.Fatal(err)
	}
	getIP := func(name string) (v1.IP, error) {
		var x v1.IP
		err := admin.Get(ctx, "IP", "web3", name, &x)
		return x, err
	}
	getSilo := func(name string) v1.Silo {
		var s v1.Silo
		_ = admin.Get(ctx, "Silo", "web3", name, &s)
		return s
	}
	node := func(name, class, ip, source string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"},
			Spec: v1.SiloSpec{Runtime: "docker", Image: "geth", Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Service: &v1.SiloService{Expose: v1.ExposeLoadBalancer, Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}},
					LoadBalancer: &v1.LoadBalancerSpec{Class: class, IP: ip}},
				Network: v1.SiloNetwork{Egress: v1.Egress{Source: source}}}}
	}

	// ── An IP made by hand: reserved before any service ──
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "eth", Namespace: "web3"},
		Spec: v1.IPSpec{Class: kplugintest.ClassIP, Region: "ca-central"}}); err != nil {
		t.Fatal(err)
	}
	var addr string
	eventually("eth reserved, held by nobody", func() (bool, string) {
		x, _ := getIP("eth")
		addr = x.Status.Address
		return addr != "" && x.Status.BoundTo == "" && x.Status.Region == "ca-central", condMsgs(x.Status.Conditions)
	})
	// A silo's service takes it, in and out.
	if err := admin.Create(ctx, node("node-1", kplugintest.ClassIP, "eth", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	eventually("node-1 holds eth and sends from it", func() (bool, string) {
		x, _ := getIP("eth")
		s := getSilo("node-1")
		st := s.Status.Service
		return x.Status.BoundTo == "silo/node-1" && s.Status.Host == "w1" && st.PublicIP == addr && st.EgressIP == addr && st.IP == "eth" && st.Announce,
			x.Status.BoundTo + " " + st.AddressesLine() + " " + condMsgs(s.Status.Conditions)
	})
	if line := getSilo("node-1").Status.Service.AddressesLine(); line != "same address in and out: "+addr {
		t.Errorf("in and out: %q", line)
	}
	// Bound: it can't be deleted, nor taken by another.
	if err := admin.Delete(ctx, "IP", "web3", "eth"); !client.IsConflict(err) || !strings.Contains(err.Error(), "held by silo/node-1") {
		t.Fatalf("deleting a bound IP: %v", err)
	}
	if err := admin.Create(ctx, node("node-2", kplugintest.ClassIP, "eth", "")); !client.IsConflict(err) || !strings.Contains(err.Error(), "held by silo/node-1") {
		t.Fatalf("naming a bound IP: %v", err)
	}
	// The silo goes; the address stays, unshared from the host, still reserved.
	if err := admin.Delete(ctx, "Silo", "web3", "node-1"); err != nil {
		t.Fatal(err)
	}
	eventually("eth let go, still reserved with its address", func() (bool, string) {
		x, err := getIP("eth")
		_, shared := fake.LBOf("web3", "node-1")
		_, _, _ = fake.Snapshot()
		return err == nil && x.Status.BoundTo == "" && x.Status.Address == addr && !shared, x.Status.BoundTo
	})
	// A new silo takes it and gets the same address.
	if err := admin.Create(ctx, node("node-3", kplugintest.ClassIP, "eth", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	eventually("node-3 holds eth: the same address", func() (bool, string) {
		s := getSilo("node-3")
		return s.Status.Service.PublicIP == addr && s.Status.Service.EgressIP == addr, s.Status.Service.AddressesLine() + " " + condMsgs(s.Status.Conditions)
	})

	// ── A service that names no IP gets one, named after it, that goes with it ──
	if err := admin.Create(ctx, node("web", kplugintest.ClassLB, "", "")); err != nil {
		t.Fatal(err)
	}
	var webAddr string
	eventually("web's IP made for it, with the balancer's address", func() (bool, string) {
		x, err := getIP("web")
		s := getSilo("web")
		webAddr = x.Status.Address
		return err == nil && !x.Kept() && len(x.OwnerReferences) == 1 && x.Status.BoundTo == "silo/web" && webAddr != "" &&
				s.Status.Service.PublicIP == webAddr && s.Status.Service.EgressIP == "203.0.113.5" && strings.Contains(s.Status.Service.EgressNote, "on no host"),
			condMsgs(x.Status.Conditions) + " " + s.Status.Service.AddressesLine()
	})
	if err := admin.Delete(ctx, "Silo", "web3", "web"); err != nil {
		t.Fatal(err)
	}
	eventually("web's IP gone with it, and its balancer", func() (bool, string) {
		_, err := getIP("web")
		_, there := fake.LBOf("web3", "web")
		return client.IsNotFound(err) && !there, ""
	})
	// Unless kept: kvo ip keep drops the ownership and keeps the address; the balancer stays, parked.
	if err := admin.Create(ctx, node("keeper", kplugintest.ClassLB, "", "")); err != nil {
		t.Fatal(err)
	}
	var keptAddr string
	eventually("keeper's IP made", func() (bool, string) {
		x, _ := getIP("keeper")
		keptAddr = x.Status.Address
		return keptAddr != "" && x.Status.BoundTo == "silo/keeper", condMsgs(x.Status.Conditions)
	})
	for i := 0; ; i++ {
		x, _ := getIP("keeper")
		x.Spec.Reclaim, x.OwnerReferences = v1.ReclaimRetain, nil
		err := admin.Update(ctx, &x)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || i > 10 {
			t.Fatal(err)
		}
	}
	if err := admin.Delete(ctx, "Silo", "web3", "keeper"); err != nil {
		t.Fatal(err)
	}
	eventually("keeper's IP kept, unbound, same address; its balancer parked", func() (bool, string) {
		x, err := getIP("keeper")
		lbs, _, _ := fake.Snapshot()
		lb, ok := lbs[x.UID]
		_, gone := getSilo("keeper"), client.IsNotFound(admin.Get(ctx, "Silo", "web3", "keeper", &v1.Silo{}))
		return err == nil && gone && x.Status.BoundTo == "" && x.Status.Address == keptAddr && ok && len(lb.Backends) == 0 && len(lb.Ports) == 0,
			x.Status.BoundTo + " " + x.Status.Address
	})

	// ── Same IP out as in: refused where the address is on no host ──
	if err := admin.Create(ctx, node("p2p", kplugintest.ClassLB, "", v1.EgressSameAsService)); !client.IsInvalid(err) || !strings.Contains(err.Error(), "on no host") {
		t.Fatalf("sameAsService behind a balancer: %v", err)
	}
	// An IP of a class that can't reserve isn't made by hand.
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "nb", Namespace: "web3"},
		Spec: v1.IPSpec{Class: kplugintest.ClassLB}}); !client.IsInvalid(err) || !strings.Contains(err.Error(), "kvo ip keep") {
		t.Fatalf("an IP of fake-lb by hand: %v", err)
	}

	// ── ip-pool: a host's own addresses, one per silo, in and out ──
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "own", Namespace: "web3"},
		Spec: v1.IPSpec{Class: v1.LBIPPool}}); err != nil {
		t.Fatal(err)
	}
	eventually("own reserved on w1", func() (bool, string) {
		x, _ := getIP("own")
		return x.Status.Host == "w1" && x.Status.Address == "192.0.2.17", condMsgs(x.Status.Conditions)
	})
	if err := admin.Create(ctx, node("pooled", v1.LBIPPool, "own", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, node("pooled-2", v1.LBIPPool, "", "")); err != nil {
		t.Fatal(err)
	}
	eventually("pooled on own's address in and out; pooled-2 on the next one, out the host's", func() (bool, string) {
		a, b := getSilo("pooled").Status.Service, getSilo("pooled-2").Status.Service
		return a.PublicIP == "192.0.2.17" && a.EgressIP == "192.0.2.17" && len(a.HostAddresses) == 1 &&
				b.PublicIP == "192.0.2.18" && b.EgressIP == "203.0.113.5" && strings.Contains(b.EgressNote, "sameAsService sends from 192.0.2.18"),
			a.AddressesLine() + " | " + b.AddressesLine()
	})
	// An address in use stays on the host.
	var h v1.Host
	if err := admin.Get(ctx, "Host", "", "w1", &h); err != nil {
		t.Fatal(err)
	}
	h.Spec.Network.Addresses = []string{"192.0.2.18"}
	if err := admin.Update(ctx, &h); !client.IsConflict(err) || !strings.Contains(err.Error(), "192.0.2.17 (IP web3/own)") {
		t.Fatalf("removing an address in use: %v", err)
	}
}
