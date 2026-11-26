package integration

import (
	"context"
	"errors"
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

// IP objects in a real control plane with the fake plugin (networking v2): a Provider IP made by
// hand is reserved before any service; a silo's HostPort service on it holds it (one holder at a
// time: a second silo naming it waits); a held IP can't be deleted; the silo goes and the address
// stays, the waiting silo gets the same address; a Host IP takes its host's extra address, which
// the host can't drop while the IP has it; deleting the IP releases the address at the provider.
// ipRig is a real control plane with the fake plugin and one worker of its, w1 (host address
// mail: 203.0.113.21), heartbeating.
type ipRig struct {
	ctx        context.Context
	admin      *client.Client
	fake       *kplugintest.Fake
	eventually func(what string, cond func() (bool, string))
}

func newIPRig(t *testing.T) *ipRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	dir, _ := os.MkdirTemp("/tmp", "kvi")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	fake := kplugintest.New()
	fake.Machines["203.0.113.5"] = kplugin.HostInfo{ID: "42", Region: "ca-central"}
	reg := &plugins.Registry{Dir: filepath.Join(dir, "plugins")}
	if err := reg.Add(ctx, fake); err != nil {
		t.Fatal(err)
	}
	cp, err := controlplane.Start(ctx, controlplane.Config{Create: true, ClusterName: "it", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond,
		Plugins: reg})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cp.Wait() }) // stopped before its folder goes (cleanups run last first)
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
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
	w1 := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "w1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.5", Addresses: []v1.HostAddress{{Name: "mail", Kind: v1.NetworkExternal, Address: "203.0.113.21"}},
			Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
	if err := admin.Create(ctx, w1); err != nil {
		t.Fatal(err)
	}
	beat := func(h *v1.Host) {
		now := time.Now().UTC().Truncate(time.Second)
		meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}, now)
		h.Status.LastHeartbeat = &now
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 8, Memory: "16Gi"}
	}
	writeHostStatus(ctx, t, admin, w1, beat)
	go func() { // the worker's heartbeats
		for ctx.Err() == nil {
			var h v1.Host
			if admin.Get(ctx, "Host", "", "w1", &h) == nil {
				beat(&h)
				_ = admin.UpdateStatus(ctx, &h)
			}
			time.Sleep(time.Second)
		}
	}()
	eventually("w1 recognised as the plugin's", func() (bool, string) {
		var h v1.Host
		_ = admin.Get(ctx, "Host", "", "w1", &h)
		return h.Status.Provider != nil && h.Status.Provider.ID == "42", ""
	})
	return &ipRig{ctx: ctx, admin: admin, fake: fake, eventually: eventually}
}

func TestIPs(t *testing.T) {
	r := newIPRig(t)
	ctx, admin, fake, eventually := r.ctx, r.admin, r.fake, r.eventually
	if err := admin.Create(ctx, ns("mail")); err != nil {
		t.Fatal(err)
	}
	ip := func(name string) (*v1.IP, error) {
		var x v1.IP
		err := admin.Get(ctx, "IP", "mail", name, &x)
		return &x, err
	}
	silo := func(name string) *v1.Silo {
		return &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "mail"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "postfix"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
				Ports: []v1.SiloPort{{Name: "smtp", Port: 2525}},
				Services: []v1.SiloService{{Name: name, Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge"},
					Ports: []v1.ServicePort{{Port: "smtp", As: 25}}}},
				Network: v1.SiloNetwork{Egress: v1.Egress{Source: &v1.EgressSource{IP: "mail"}}}}}
	}

	// Reserved before any service.
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "edge", Namespace: "mail"},
		Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "fake", Region: "ca-central"}}); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "mail"},
		Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}}); err != nil {
		t.Fatal(err)
	}
	addr := ""
	eventually("edge reserved, mail on w1's address", func() (bool, string) {
		e, _ := ip("edge")
		m, _ := ip("mail")
		addr = e.Status.Address
		return addr != "" && e.Status.Handle != "" && e.Status.Where == "fake ca-central" && e.Status.Holder == nil &&
				m.Status.Address == "203.0.113.21" && m.Status.Host == "w1" && m.Status.Where == "host w1",
			fmt.Sprintf("edge %+v; mail %+v", e.Status, m.Status)
	})

	// The first silo naming them holds them; the second waits, told who has them.
	if err := admin.Create(ctx, silo("blue")); err != nil {
		t.Fatal(err)
	}
	eventually("blue holds edge and mail, on w1", func() (bool, string) {
		e, _ := ip("edge")
		m, _ := ip("mail")
		return e.Status.Holders() == "silo/blue (25/TCP)" && e.Status.Host == "w1" && m.Status.Holder != nil && m.Status.Holder.Holder == "silo/blue",
			fmt.Sprintf("edge %+v; mail %+v", e.Status, m.Status)
	})
	eventually("edge's address shared with w1, blue's host", func() (bool, string) {
		e, _ := ip("edge")
		lbs, _, _ := fake.Snapshot()
		lb, ok := lbs[e.UID]
		return ok && lb.Class == kplugintest.ClassIP && lb.Address == addr && len(lb.Backends) == 1 && lb.Backends[0].Name == "w1" &&
			meta.IsTrue(e.Status.Conditions, "Shared"), fmt.Sprintf("%+v %+v", lb, e.Status.Conditions)
	})
	if err := admin.Create(ctx, silo("green")); err != nil {
		t.Fatal(err)
	}
	eventually("green waits for edge", func() (bool, string) {
		e, _ := ip("edge")
		return len(e.Status.Waiting) == 1 && e.Status.Waiting[0].Holder == "silo/green", fmt.Sprintf("%+v", e.Status)
	})

	// A held IP can't be deleted; a host address an IP has can't leave its host.
	var ce *client.Error
	if err := admin.Delete(ctx, "IP", "mail", "edge"); !errors.As(err, &ce) || ce.Code != http.StatusConflict {
		t.Fatalf("deleting a held IP: %v, want 409", err)
	}
	var h v1.Host
	if err := admin.Get(ctx, "Host", "", "w1", &h); err != nil {
		t.Fatal(err)
	}
	h.Spec.Addresses = nil
	if err := admin.Update(ctx, &h); err == nil {
		t.Fatal("w1 dropped address mail while IP mail/mail has it")
	}

	// Blue goes: the IPs are kept, and green gets the same addresses.
	if err := admin.Delete(ctx, "Silo", "mail", "blue"); err != nil {
		t.Fatal(err)
	}
	eventually("green holds edge, the same address", func() (bool, string) {
		e, _ := ip("edge")
		m, _ := ip("mail")
		return e.Status.Holder != nil && e.Status.Holder.Holder == "silo/green" && e.Status.Address == addr &&
			m.Status.Holder != nil && m.Status.Holder.Holder == "silo/green" && m.Status.Address == "203.0.113.21", fmt.Sprintf("%+v", e.Status)
	})

	// Green goes too; then the IPs can be deleted, and the provider's address is released.
	if err := admin.Delete(ctx, "Silo", "mail", "green"); err != nil {
		t.Fatal(err)
	}
	eventually("edge and mail deleted, the address released", func() (bool, string) {
		for _, n := range []string{"edge", "mail"} {
			err := admin.Delete(ctx, "IP", "mail", n)
			if err != nil && !client.IsNotFound(err) {
				return false, err.Error()
			}
		}
		_, e := ip("edge")
		_, m := ip("mail")
		lbs, _, _ := fake.Snapshot()
		return len(lbs) == 0 && client.IsNotFound(e) && client.IsNotFound(m) && slices.ContainsFunc(fake.CallLog(), func(c string) bool { return strings.HasPrefix(c, "release-address") }),
			fmt.Sprint(e, m, fake.CallLog())
	})
}

// Deleting a namespace with what is in it releases what it reserved, in order: its silos (and
// with them their balancers), its Services (their balancers), then its IP sets and IPs (the
// provider's addresses); nothing is left at the provider.
func TestNamespaceCascadeReleasesBalancersAndIPs(t *testing.T) {
	r := newIPRig(t)
	ctx, admin, fake, eventually := r.ctx, r.admin, r.fake, r.eventually
	if err := admin.Create(ctx, ns("shop")); err != nil {
		t.Fatal(err)
	}
	web := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "shop", Labels: map[string]string{"app": "web"}},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "nginx"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"},
			Ports: []v1.SiloPort{{Name: "http", Port: 8080}},
			Services: []v1.SiloService{{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "fake"},
				Ports: []v1.ServicePort{{Port: "http", As: 80}}}}}}
	relay := &v1.SiloSet{TypeMeta: tm("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: "relay", Namespace: "shop"},
		Spec: v1.SiloSetSpec{Instances: 1, IPs: "pool", Template: v1.SiloTemplate{SiloSpec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "postfix"},
			Resources: v1.Resources{CPU: 1, Memory: "256Mi"}, Ports: []v1.SiloPort{{Name: "smtp", Port: 2525}},
			Services: []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Own: true}, Ports: []v1.ServicePort{{Port: "smtp", As: 25}}}}}}}}
	for _, o := range []meta.Object{
		web,
		&v1.Service{TypeMeta: tm("Service"), ObjectMeta: meta.ObjectMeta{Name: "group", Namespace: "shop"},
			Spec: v1.ServiceSpec{Selector: map[string]string{"app": "web"}, Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "fake"},
				Ports: []v1.ServicePortSpec{{Name: "http", Port: 8080, TargetPort: "http"}}}},
		&v1.IPSet{TypeMeta: tm("IPSet"), ObjectMeta: meta.ObjectMeta{Name: "pool", Namespace: "shop"},
			Spec: v1.IPSetSpec{Type: v1.IPSetDynamic, Provider: "fake", Region: "ca-central", Max: 2}},
		relay,
	} {
		if err := admin.Create(ctx, o); err != nil {
			t.Fatal(err)
		}
	}
	// The agent's part: web runs where it was placed.
	eventually("web running", func() (bool, string) {
		var s v1.Silo
		if err := admin.Get(ctx, "Silo", "shop", "web", &s); err != nil || s.Status.Host == "" {
			return false, "not placed"
		}
		if s.Status.Phase == "Running" {
			return true, ""
		}
		s.Status.Phase, s.Status.SiloIP = "Running", "10.64.0.7"
		return false, fmt.Sprint(admin.UpdateStatus(ctx, &s))
	})
	eventually("two balancers, and pool-0 held by relay-0 and shared with its host", func() (bool, string) {
		lbs, _, _ := fake.Snapshot()
		var x v1.IP
		_ = admin.Get(ctx, "IP", "shop", "pool-0", &x)
		return len(lbs) == 3 && x.Status.Address != "" && x.Status.Holder != nil && x.Status.Holder.Holder == "silo/relay-0",
			fmt.Sprintf("%d balancers; pool-0 %+v", len(lbs), x.Status)
	})

	if err := admin.DeleteNamespace(ctx, "shop", client.DeleteOptions{Cascade: true}); err != nil {
		t.Fatal(err)
	}
	eventually("the namespace gone, nothing left at the provider", func() (bool, string) {
		var n v1.Namespace
		err := admin.Get(ctx, "Namespace", "", "shop", &n)
		lbs, _, _ := fake.Snapshot()
		return client.IsNotFound(err) && len(lbs) == 0, fmt.Sprintf("%v %v; %d balancers", n.Annotations, err, len(lbs))
	})
	// The provider was told in order: balancers removed before any address was released.
	// (A Provider IP's own unshare, delete-lb of its UID, comes right before its release.)
	released := map[string]bool{}
	for _, c := range fake.CallLog() {
		if f := strings.Fields(c); f[0] == "release-address" {
			released[f[len(f)-1]] = true
		}
	}
	lastLB, firstRelease := -1, -1
	for i, c := range fake.CallLog() {
		switch {
		case strings.HasPrefix(c, "delete-lb") && !released[strings.Fields(c)[1]]:
			lastLB = i
		case strings.HasPrefix(c, "release-address") && firstRelease < 0:
			firstRelease = i
		}
	}
	if lastLB < 0 || firstRelease < 0 || lastLB > firstRelease {
		t.Fatalf("calls %v: balancers removed, then addresses released", fake.CallLog())
	}
}
