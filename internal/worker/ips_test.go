package worker

import (
	"context"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

func hostIP(name, ns, hostAddress, addr, host, holderUID string) *v1.IP {
	x := &v1.IP{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: hostAddress}}
	x.Status.Address, x.Status.Host = addr, host
	if holderUID != "" {
		x.Status.Holder = &v1.IPHolder{Holder: "silo/x", UID: holderUID}
	}
	return x
}

func mailSilo() *v1.Silo {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: "mx", Namespace: "mail", UID: "u-mx"}}
	s.Spec.Ports = []v1.SiloPort{{Name: "smtp", Port: 2525}, {Name: "web", Port: 8080}}
	s.Spec.Services = []v1.SiloService{
		{Name: "mx", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "mail"}, Ports: []v1.ServicePort{{Port: "smtp", As: 25}}},
		{Name: "webmail", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: 443}}},
	}
	s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "mail"}
	s.Status.Host, s.Status.SiloIP, s.Status.Phase = "metal-1", "10.64.0.2", "Running"
	return s
}

func TestWithIPs(t *testing.T) {
	me := &v1.Host{ObjectMeta: meta.ObjectMeta{Name: "metal-1"}, Spec: v1.HostSpec{ExternalIP: "198.51.100.10",
		Addresses: []v1.HostAddress{{Name: "mail", Kind: v1.NetworkExternal, Address: "198.51.100.21"}, {Name: "spare", Kind: v1.NetworkExternal, Address: "198.51.100.22"}}}}
	s := mailSilo()
	view := func(ips ...*v1.IP) kni.Silo {
		v := WithIPs(NetworkView("metal-1", me, []*v1.Silo{s}, nil, nil), "metal-1", me, []*v1.Silo{s}, ips)
		return v.Local[0]
	}
	for _, c := range []struct {
		name     string
		ip       *v1.IP
		want     string // the mx service's address, and the address out
		hostAddr bool   // on the uplink
	}{
		{"held here", hostIP("mail", "mail", "mail", "198.51.100.21", "metal-1", "u-mx"), "198.51.100.21", true},
		{"held by another silo", hostIP("mail", "mail", "mail", "198.51.100.21", "metal-1", "u-other"), "", false},
		{"held by nobody", hostIP("mail", "mail", "mail", "198.51.100.21", "metal-1", ""), "", false},
		{"on another host", hostIP("mail", "mail", "mail", "198.51.100.21", "metal-2", "u-mx"), "", false},
		{"no address yet", hostIP("mail", "mail", "mail", "", "metal-1", "u-mx"), "", false},
		{"another namespace's IP of that name", hostIP("mail", "other", "mail", "198.51.100.21", "metal-1", "u-mx"), "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ks := view(c.ip)
			got, out := ks.Addrs["mx"].String(), ks.EgressIP.String()
			if !ks.Addrs["mx"].IsValid() {
				got = ""
			}
			if !ks.EgressIP.IsValid() {
				out = ""
			}
			if got != c.want || out != c.want || ks.Addrs["webmail"].IsValid() {
				t.Fatalf("addrs %v, out %q, want %q", ks.Addrs, out, c.want)
			}
			if held := HeldAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{c.ip}); slices.Contains(held, "198.51.100.21") != c.hostAddr {
				t.Fatalf("held addresses %v", held)
			}
		})
	}
	// The host's named extra addresses are never reached from a silo, held or not.
	v := WithIPs(NetworkView("metal-1", me, []*v1.Silo{s}, nil, nil), "metal-1", me, []*v1.Silo{s}, nil)
	if len(v.OwnIPs) != 2 || v.OwnIPs[0].String() != "198.51.100.21" || v.OwnIPs[1].String() != "198.51.100.22" {
		t.Fatalf("own IPs %v", v.OwnIPs)
	}
	// A Provider IP counts where its holder runs.
	p := &v1.IP{ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "mail"}, Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}}
	p.Status.Address, p.Status.Holder = "172.233.1.5", &v1.IPHolder{Holder: "silo/mx", UID: "u-mx"}
	if ks := view(p); ks.Addrs["mx"].String() != "172.233.1.5" || ks.EgressIP.String() != "172.233.1.5" {
		t.Fatalf("provider IP: %+v %v", ks.Addrs, ks.EgressIP)
	}
	// On the uplink, unless its provider announces it: then on the loopback (the node side's BGP).
	if held, lo := HeldAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{p}), AnnouncedIPAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{p}); !slices.Contains(held, "172.233.1.5") || len(lo) != 0 {
		t.Fatalf("provider IP, not announced: uplink %v, loopback %v", held, lo)
	}
	p.Status.Announce = true
	if held, lo := HeldAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{p}), AnnouncedIPAddresses("metal-1", []*v1.Silo{s}, []*v1.IP{p}); len(held) != 0 || !slices.Equal(lo, []string{"172.233.1.5"}) {
		t.Fatalf("provider IP, announced: uplink %v, loopback %v", held, lo)
	}
	if lo := AnnouncedIPAddresses("metal-2", []*v1.Silo{s}, []*v1.IP{p}); len(lo) != 0 {
		t.Fatalf("announced on a host its holder isn't on: %v", lo)
	}
	if ks := view(p); ks.Addrs["mx"].String() != "172.233.1.5" || ks.EgressIP.String() != "172.233.1.5" {
		t.Fatalf("announced provider IP: in %+v, out %v", ks.Addrs, ks.EgressIP)
	}
	p.Status.Announce = false
	// A balancer's IP never sends out.
	lb := mailSilo()
	lb.Spec.Services = append(lb.Spec.Services, v1.SiloService{Name: "front", Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "azure", IP: "mail"}, Ports: []v1.ServicePort{{Port: "web"}}})
	if e := egressHere("metal-1", lb, []*v1.IP{p}); e.IsValid() {
		t.Fatalf("out from a balancer's IP: %v", e)
	}
}

// own: a SiloSet instance's member of the set's IPSet (labelled, held by the instance).
func TestOwnIP(t *testing.T) {
	s := mailSilo()
	s.Name, s.UID = "mx-1", "u-mx-1"
	s.Spec.Services[0].HostPort = &v1.HostPortSource{Own: true}
	s.Spec.Network.Egress.Source = &v1.EgressSource{Own: true}
	member := hostIP("edge-1", "mail", "edge-a", "198.51.100.31", "metal-1", "u-mx-1")
	member.Labels = map[string]string{v1.LabelIPSet: "edge", v1.LabelIPSetOrdinal: "1"}
	unlabelled := hostIP("other", "mail", "edge-b", "198.51.100.32", "metal-1", "u-mx-1")
	ks := WithIPs(NetworkView("metal-1", nil, []*v1.Silo{s}, nil, nil), "metal-1", nil, []*v1.Silo{s}, []*v1.IP{unlabelled, member}).Local[0]
	if ks.Addrs["mx"].String() != "198.51.100.31" || ks.EgressIP.String() != "198.51.100.31" {
		t.Fatalf("own: %v %v", ks.Addrs, ks.EgressIP)
	}
}

// The network loop end to end against an API server: a HostPort on a Host IP opens on that IP's
// address once the silo holds it (and not before), and egress leaves from it.
func TestNetworkLoopOpensOnTheIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	api := httptest.NewServer(srv)
	defer api.Close()
	admin := client.New(api.URL)
	tm := func(kind string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: kind} }
	h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: "metal-1"},
		Spec: v1.HostSpec{ExternalIP: "198.51.100.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}},
			Addresses: []v1.HostAddress{{Name: "mail", Kind: v1.NetworkExternal, Address: "198.51.100.21"}}}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(admin.Create(ctx, h))
	must(admin.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "mail"}}))
	ip := &v1.IP{TypeMeta: tm("IP"), ObjectMeta: meta.ObjectMeta{Name: "mail", Namespace: "mail"}, Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "mail"}}
	must(admin.Create(ctx, ip))
	s := mailSilo()
	s.TypeMeta, s.UID, s.Status = tm("Silo"), "", v1.SiloStatus{}
	s.Spec.Runtime, s.Spec.Container, s.Spec.Resources = "docker", &v1.ContainerSource{Image: "nginx"}, v1.Resources{CPU: 1, Memory: "1Gi"}
	must(admin.Create(ctx, s))
	must(admin.Get(ctx, "Silo", "mail", "mx", s))
	s.Status.Host, s.Status.SiloIP, s.Status.Phase = "metal-1", "10.64.0.2", "Running"
	must(admin.UpdateStatus(ctx, s))

	applied := make(chan string, 64)
	old := applyRules
	applyRules = func(_ context.Context, rules string) error { applied <- rules; return nil }
	defer func() { applyRules = old }()
	done := make(chan struct{})
	go func() {
		RunNetworkWith(ctx, client.New(api.URL), "metal-1", nil, nil, func(string, ...any) {}, NetworkOptions{})
		close(done)
	}()
	defer func() { cancel(); <-done; api.CloseClientConnections() }()
	wait := func(what string, ok func(string) bool) string {
		t.Helper()
		for {
			select {
			case r := <-applied:
				if ok(r) {
					return r
				}
			case <-ctx.Done():
				t.Fatalf("never: %s", what)
			}
		}
	}
	const onIP = "ip daddr 198.51.100.21 tcp dport 25 dnat ip to 10.64.0.2:2525"
	const outIP = "snat ip to 198.51.100.21"
	r := wait("the worker's port", func(r string) bool { return strings.Contains(r, "dport 443 dnat ip to 10.64.0.2:8080") })
	if strings.Contains(r, onIP) || strings.Contains(r, outIP) {
		t.Fatal("opened on the IP before the silo holds it")
	}
	must(admin.Get(ctx, "IP", "mail", "mail", ip))
	ip.Status.Address, ip.Status.Host = "198.51.100.21", "metal-1"
	ip.Status.Holder = &v1.IPHolder{Holder: "silo/mx", UID: s.UID}
	must(admin.UpdateStatus(ctx, ip))
	wait("the IP's port and egress", func(r string) bool { return strings.Contains(r, onIP) && strings.Contains(r, outIP) })
}
