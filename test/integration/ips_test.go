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
// stays, a new silo takes the same address; an exclusive (announced) IP someone holds can't be
// deleted or taken. Load-balancer services naming no IP share the namespace's default for their
// class, one balancer with each one's ports; a port clash is refused; dedicated gets its own; the
// default goes with its last service, a kept one stays (its balancer parked); an annotation the
// plugin doesn't know shows as a condition; sameAsService behind a balancer is refused; ip-pool
// hands out a host's own addresses, which can't be taken from the host while in use.
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
	for _, name := range []string{"w1"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}},
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
	node := func(name, class, ip, source string, port ...int) *v1.Silo {
		p := 30303
		if len(port) > 0 {
			p = port[0]
		}
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "geth"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Ports: []v1.SiloPort{{Name: "p2p", Port: p}},
				Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "p2p", LoadBalancer: true}},
					LoadBalancer: &v1.LoadBalancerSpec{Class: class, IP: ip}},
				Network: v1.SiloNetwork{Egress: v1.Egress{Source: source}}}}
	}
	holders := func(x v1.IP) string {
		var out []string
		for _, h := range x.Status.BoundTo {
			out = append(out, h.Holder)
		}
		return strings.Join(out, ",")
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
		return addr != "" && len(x.Status.BoundTo) == 0 && x.Status.Region == "ca-central", condMsgs(x.Status.Conditions)
	})
	// A silo's service takes it, in and out.
	if err := admin.Create(ctx, node("node-1", kplugintest.ClassIP, "eth", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	eventually("node-1 holds eth and sends from it", func() (bool, string) {
		x, _ := getIP("eth")
		s := getSilo("node-1")
		st := s.Status.Service
		return holders(x) == "silo/node-1" && s.Status.Host == "w1" && st.LoadBalancerIP == addr && st.EgressIP == addr && st.IP == "eth" && st.Announce,
			holders(x) + " " + st.AddressesLine() + " " + condMsgs(s.Status.Conditions)
	})
	if line := getSilo("node-1").Status.Service.AddressesLine(); line != "same address in and out: "+addr {
		t.Errorf("in and out: %q", line)
	}
	// Held (and exclusive: one host announces it): it can't be deleted, nor taken by another.
	if err := admin.Delete(ctx, "IP", "web3", "eth"); !client.IsConflict(err) || !strings.Contains(err.Error(), "held by silo/node-1") {
		t.Fatalf("deleting a bound IP: %v", err)
	}
	if err := admin.Create(ctx, node("node-2", kplugintest.ClassIP, "eth", "", 9000)); !client.IsConflict(err) || !strings.Contains(err.Error(), "held by silo/node-1") {
		t.Fatalf("naming a bound IP: %v", err)
	}
	// The silo goes; the address stays, unshared from the host, still reserved.
	if err := admin.Delete(ctx, "Silo", "web3", "node-1"); err != nil {
		t.Fatal(err)
	}
	eventually("eth let go, still reserved with its address", func() (bool, string) {
		x, err := getIP("eth")
		_, shared := fake.LBOf("web3", "silo/node-1")
		return err == nil && len(x.Status.BoundTo) == 0 && x.Status.Address == addr && !shared, holders(x)
	})
	// A new silo takes it and gets the same address.
	if err := admin.Create(ctx, node("node-3", kplugintest.ClassIP, "eth", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	eventually("node-3 holds eth: the same address", func() (bool, string) {
		s := getSilo("node-3")
		return s.Status.Service.LoadBalancerIP == addr && s.Status.Service.EgressIP == addr, s.Status.Service.AddressesLine() + " " + condMsgs(s.Status.Conditions)
	})

	// ── Shared by default: two silos naming no IP, one address, one balancer, their own ports ──
	def := v1.DefaultIPName(kplugintest.ClassLB)
	if err := admin.Create(ctx, node("web", kplugintest.ClassLB, "", "", 80)); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, node("rpc", kplugintest.ClassLB, "", "", 8545)); err != nil {
		t.Fatal(err)
	}
	var shared string
	eventually("web and rpc on the namespace's default IP, one balancer with both ports", func() (bool, string) {
		x, err := getIP(def)
		w, r := getSilo("web").Status.Service, getSilo("rpc").Status.Service
		shared = x.Status.Address
		lbs, _, _ := fake.Snapshot()
		lb := lbs[x.UID]
		svcs := map[string]bool{}
		for _, p := range lb.Ports {
			svcs[p.Service] = len(p.Backends) == 1
		}
		return err == nil && !x.Kept() && x.Labels[v1.LabelDefaultIP] == kplugintest.ClassLB && len(x.Status.BoundTo) == 2 && shared != "" &&
				w.LoadBalancerIP == shared && r.LoadBalancerIP == shared && w.IP == def && len(lb.Ports) == 2 && svcs["silo/web"] && svcs["silo/rpc"] &&
				strings.Contains(w.EgressNote, "on no host"),
			holders(x) + " " + condMsgs(x.Status.Conditions) + " | " + w.AddressesLine() + " | " + r.AddressesLine()
	})
	// The one refusal: a port another service has on that address.
	if err := admin.Create(ctx, node("web-2", kplugintest.ClassLB, "", "", 80)); !client.IsConflict(err) || !strings.Contains(err.Error(), "port 80/TCP on IP "+def+" is silo/web's") {
		t.Fatalf("a port clash on the shared IP: %v", err)
	}
	// dedicated: an IP of its own, another address, even on the same port.
	own := node("own", kplugintest.ClassLB, "", "", 80)
	own.Spec.Service.LoadBalancer.Dedicated = true
	if err := admin.Create(ctx, own); err != nil {
		t.Fatal(err)
	}
	eventually("own on an IP of its own, another address", func() (bool, string) {
		x, _ := getIP("own")
		st := getSilo("own").Status.Service
		return holders(x) == "silo/own" && len(x.OwnerReferences) == 1 && x.Status.Address != "" && x.Status.Address != shared && st.LoadBalancerIP == x.Status.Address,
			holders(x) + " " + condMsgs(x.Status.Conditions)
	})
	// sameAsService behind a balancer: refused, the address is on no host.
	if err := admin.Create(ctx, node("p2p", kplugintest.ClassLB, "", v1.EgressSameAsService, 9001)); !client.IsInvalid(err) || !strings.Contains(err.Error(), "on no host") {
		t.Fatalf("sameAsService behind a balancer: %v", err)
	}
	// A knob the plugin doesn't know: refused by it, shown on the IP and the silo.
	knobs := node("knobs", kplugintest.ClassLB, "", "", 81)
	knobs.Spec.Service.LoadBalancer.Dedicated = true
	knobs.Annotations = map[string]string{"fake.kevaso.com/no-such-knob": "on", "example.com/not-the-plugins": "ignored"}
	if err := admin.Create(ctx, knobs); err != nil {
		t.Fatal(err)
	}
	eventually("the unknown annotation refused, saying so", func() (bool, string) {
		x, _ := getIP("knobs")
		s := getSilo("knobs")
		c := meta.FindCondition(s.Status.Conditions, "LoadBalancer")
		ic := meta.FindCondition(x.Status.Conditions, "LoadBalancer")
		return c != nil && c.Status == meta.ConditionFalse && strings.Contains(c.Message, "unknown annotation fake.kevaso.com/no-such-knob") &&
			ic != nil && ic.Reason == "Failed", condMsgs(s.Status.Conditions)
	})
	// The shared IP stays while a service is on it, and goes with the last.
	if err := admin.Delete(ctx, "Silo", "web3", "web"); err != nil {
		t.Fatal(err)
	}
	eventually("rpc alone on the default, same address; web's port gone from the balancer", func() (bool, string) {
		x, err := getIP(def)
		_, webThere := fake.LBOf("web3", "silo/web")
		return err == nil && holders(x) == "silo/rpc" && x.Status.Address == shared && !webThere, holders(x)
	})
	if err := admin.Delete(ctx, "Silo", "web3", "rpc"); err != nil {
		t.Fatal(err)
	}
	eventually("the default IP gone with its last service, and its balancer", func() (bool, string) {
		_, err := getIP(def)
		_, there := fake.LBOf("web3", "silo/rpc")
		return client.IsNotFound(err) && !there, ""
	})
	// Unless kept: kvo ip keep; the silo goes; the address stays, its balancer parked.
	for i := 0; ; i++ {
		x, err := getIP("own")
		if err != nil {
			t.Fatalf("own: %v", err)
		}
		x.Spec.Reclaim, x.OwnerReferences = v1.ReclaimRetain, nil
		err = admin.Update(ctx, &x)
		if err == nil {
			break
		}
		if !client.IsConflict(err) || i > 10 {
			t.Fatal(err)
		}
	}
	ownIP, _ := getIP("own")
	if err := admin.Delete(ctx, "Silo", "web3", "own"); err != nil {
		t.Fatal(err)
	}
	eventually("own kept, held by nobody, same address; its balancer parked", func() (bool, string) {
		x, err := getIP("own")
		lbs, _, _ := fake.Snapshot()
		lb, ok := lbs[x.UID]
		gone := client.IsNotFound(admin.Get(ctx, "Silo", "web3", "own", &v1.Silo{}))
		return err == nil && gone && len(x.Status.BoundTo) == 0 && x.Status.Address == ownIP.Status.Address && ok && len(lb.Backends) == 0 && len(lb.Ports) == 0,
			holders(x) + " " + x.Status.Address
	})

	// ── ip-pool: a host's own addresses, one per silo, in and out ──
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "mine", Namespace: "web3"},
		Spec: v1.IPSpec{Class: v1.LBIPPool}}); err != nil {
		t.Fatal(err)
	}
	eventually("mine reserved on w1", func() (bool, string) {
		x, _ := getIP("mine")
		return x.Status.Host == "w1" && x.Status.Address == "192.0.2.17", condMsgs(x.Status.Conditions)
	})
	if err := admin.Create(ctx, node("pooled", v1.LBIPPool, "mine", v1.EgressSameAsService)); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, node("pooled-2", v1.LBIPPool, "", "")); err != nil {
		t.Fatal(err)
	}
	eventually("pooled on mine's address in and out; pooled-2 on the next one, out the host's", func() (bool, string) {
		a, b := getSilo("pooled").Status.Service, getSilo("pooled-2").Status.Service
		return a.LoadBalancerIP == "192.0.2.17" && a.EgressIP == "192.0.2.17" && len(a.HostAddresses) == 1 &&
				b.LoadBalancerIP == "192.0.2.18" && b.EgressIP == "203.0.113.5" && strings.Contains(b.EgressNote, "sameAsService sends from 192.0.2.18"),
			a.AddressesLine() + " | " + b.AddressesLine()
	})
	// An address in use stays on the host.
	var h v1.Host
	if err := admin.Get(ctx, "Host", "", "w1", &h); err != nil {
		t.Fatal(err)
	}
	h.Spec.Network.Addresses = []string{"192.0.2.18"}
	if err := admin.Update(ctx, &h); !client.IsConflict(err) || !strings.Contains(err.Error(), "192.0.2.17 (IP web3/mine)") {
		t.Fatalf("removing an address in use: %v", err)
	}
}
