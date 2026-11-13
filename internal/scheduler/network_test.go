package scheduler

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// exposed is a P2P node: p2p and disc (30303 TCP and UDP) on its host's external IP, rpc only
// on its silo IP.
func exposed(name, host string, f func(*v1.Silo)) *v1.Silo {
	s := silo(name)
	s.Spec.Ports = []v1.SiloPort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}}
	s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{
		{Port: "p2p", HostPort: []string{v1.NetworkExternal}}, {Port: "disc", HostPort: []string{v1.NetworkExternal}}, {Port: "rpc"}}}
	s.Status.Host = host
	if f != nil {
		f(s)
	}
	return s
}

func ipObj(name, class string, f func(*v1.IP)) *v1.IP {
	x := &v1.IP{}
	x.Name, x.Namespace, x.UID, x.Spec.Class = name, "dev", "ip-"+name, class
	if f != nil {
		f(x)
	}
	return x
}

func boundTo(s *v1.Silo) func(*v1.IP) {
	return func(x *v1.IP) { x.Status.BoundTo = []v1.IPHolder{{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID}} }
}

// onLB puts every port of s on a load balancer of class (and nowhere else).
func onLB(s *v1.Silo, class, ip string) {
	for i := range s.Spec.Service.Ports {
		s.Spec.Service.Ports[i].HostPort, s.Spec.Service.Ports[i].LoadBalancer = nil, true
	}
	s.Spec.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: class, IP: ip}
}

// Placement by address (design §7.0): a port's hostPort needs that address on the host, and the
// address and number free there; each excluded host says which rule excluded it.
func TestHostPortPlacement(t *testing.T) {
	both := func(name string) *v1.Host {
		return host(name, func(h *v1.Host) { h.Spec.InternalIP, h.Spec.ExternalIP = "10.0.0.5", "51.38.10.20" })
	}
	lan := host("lan", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.Network.BehindNAT = "192.168.1.20", true })
	bare := host("bare", func(h *v1.Host) { h.Spec.ExternalIP = "203.0.113.9" })
	https := func(name, host string, nets []string, as int) *v1.Silo {
		s := silo(name)
		s.Status.Host = host
		s.Spec.Ports = []v1.SiloPort{{Name: "https", Port: 8443}}
		s.Spec.Service = &v1.SiloService{Ports: []v1.ServicePort{{Port: "https", HostPort: nets, As: as}}}
		return s
	}
	cases := []struct {
		name     string
		silo     *v1.Silo
		hosts    []*v1.Host
		placed   []*v1.Silo
		want     string            // "" : nowhere
		excluded map[string]string // host → a substring of its reason
	}{
		{"external: only hosts with an external IP", https("a", "", []string{"external"}, 443), []*v1.Host{lan, bare}, nil,
			"bare", map[string]string{"lan": "no external IP, which port 443/TCP asks for (hostPort: [external])"}},
		{"internal: a host with only an external IP can't", https("a", "", []string{"internal"}, 0), []*v1.Host{bare}, nil,
			"", map[string]string{"bare": "no internal IP, which port 8443/TCP asks for"}},
		{"both: needs both", https("a", "", []string{"internal", "external"}, 0), []*v1.Host{lan, bare, both("hv1")}, nil,
			"hv1", map[string]string{"lan": "no external IP", "bare": "no internal IP"}},
		{"behind NAT with an internal IP is an ordinary host", https("a", "", []string{"internal"}, 0), []*v1.Host{lan}, nil, "lan", nil},
		{"the same address and number: elsewhere", https("b", "", []string{"external"}, 443), []*v1.Host{both("hv1"), both("hv2")},
			[]*v1.Silo{https("a", "hv1", []string{"external"}, 443)},
			"hv2", map[string]string{"hv1": "port 443/TCP on the external IP (51.38.10.20) is held by dev/a"}},
		{"as counts, not the silo's number", https("b", "", []string{"external"}, 443), []*v1.Host{both("hv1")},
			[]*v1.Silo{func() *v1.Silo { s := https("a", "hv1", []string{"external"}, 0); s.Spec.Ports[0].Port = 443; return s }()},
			"", map[string]string{"hv1": "port 443/TCP on the external IP (51.38.10.20) is held by dev/a"}},
		{"the same number on the other address is free", https("b", "", []string{"internal"}, 443), []*v1.Host{both("hv1")},
			[]*v1.Silo{https("a", "hv1", []string{"external"}, 443)}, "hv1", nil},
		{"a number only on a silo IP holds nothing", https("b", "", []string{"external"}, 8443), []*v1.Host{both("hv1")},
			[]*v1.Silo{func() *v1.Silo { s := https("a", "hv1", nil, 0); return s }()}, "hv1", nil},
		{"no hostPort: anywhere", func() *v1.Silo { s := https("a", "", nil, 0); return s }(), []*v1.Host{lan, bare}, nil, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := Schedule(c.silo, hosts(c.hosts...), c.placed)
			if c.want != "" && d.Host != c.want {
				t.Fatalf("placed on %q, want %s: %+v", d.Host, c.want, d)
			}
			if c.want == "" && c.excluded != nil && d.Host != "" {
				t.Fatalf("placed on %s, want nowhere: %+v", d.Host, d)
			}
			for h, why := range c.excluded {
				if !strings.Contains(d.Excluded[h], why) {
					t.Errorf("%s excluded for %q, want %q", h, d.Excluded[h], why)
				}
			}
		})
	}
	// A UDP and a TCP port of the same number are different holdings.
	tcp, udp := https("a", "hv1", []string{"external"}, 0), https("b", "", []string{"external"}, 0)
	udp.Spec.Ports[0].Protocol = "UDP"
	if d, _ := Schedule(udp, hosts(both("hv1")), []*v1.Silo{tcp}); d.Host != "hv1" {
		t.Fatalf("UDP next to TCP: %+v", d)
	}
}

// Where each port is reachable, placed (status.service.ports): its silo IP, and the host
// addresses and load-balancer address it opens on, at its as number.
func TestPortStatus(t *testing.T) {
	h := host("ovh-1", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.ExternalIP = "10.0.0.5", "51.38.10.20" })
	s := silo("api-blue")
	s.Status.Host, s.Status.SiloIP = "ovh-1", "10.64.2.7"
	s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}, {Name: "debug", Port: 9229}, {Name: "unused", Port: 1}}
	s.Spec.Service = &v1.SiloService{Name: "api", Ports: []v1.ServicePort{
		{Port: "http", AllowFrom: []string{"nginx-public"}},
		{Port: "https", HostPort: []string{"external"}, As: 443},
		{Port: "metrics", HostPort: []string{"internal"}, Sources: []string{"10.0.0.0/24"}},
		{Port: "debug", HostPort: []string{"internal", "external"}},
	}}
	st, err := ServiceStatus(s, h, nil, Env{})
	want := []v1.ServicePortStatus{
		{Port: "http", Mesh: "10.64.2.7:8080"},
		{Port: "https", Mesh: "10.64.2.7:8443", External: "51.38.10.20:443"},
		{Port: "metrics", Mesh: "10.64.2.7:9090", Internal: "10.0.0.5:9090"},
		{Port: "debug", Mesh: "10.64.2.7:9229", Internal: "10.0.0.5:9229", External: "51.38.10.20:9229"},
	}
	if err != nil || st.Name != "api.dev.kevaso" || len(st.Ports) != len(want) {
		t.Fatalf("%+v %v", st, err)
	}
	for i := range want {
		if st.Ports[i] != want[i] {
			t.Errorf("port %d: %+v, want %+v", i, st.Ports[i], want[i])
		}
	}
	if got := strings.Join(st.OutsideIPs(), " "); got != "51.38.10.20 10.0.0.5" {
		t.Errorf("outside IPs %q", got)
	}
	// Another suffix, for a cluster that set one.
	if st, _ := ServiceStatus(s, h, nil, Env{Suffix: "corp"}); st.Name != "api.dev.corp" {
		t.Errorf("suffix: %s", st.Name)
	}
	// No service: no name, nothing reachable; its traffic out still has an address.
	s.Spec.Service = nil
	if st, _ := ServiceStatus(s, h, nil, Env{}); st.Name != "" || len(st.Ports) != 0 || st.EgressIP != "51.38.10.20" {
		t.Errorf("no service: %+v", st)
	}
}

func TestIPScheduling(t *testing.T) {
	lb := func(name, class string) *v1.Silo {
		return exposed(name, "", func(s *v1.Silo) {
			s.UID = "uid-" + name
			onLB(s, class, "eth")
			s.Spec.Network.Egress.Source = v1.EgressSameAsService
		})
	}
	m1 := host("metal-1", func(h *v1.Host) {
		h.Spec.ExternalIP = "198.51.100.10"
		h.Spec.Network.Addresses = []string{"198.51.100.16/30"}
	})
	m2 := host("metal-2")
	hs := hosts(m1, m2)
	a := lb("a", v1.LBIPPool)
	// Not made yet, held by another, not bound yet: nowhere.
	if d, _ := Schedule(a, hs, nil); !strings.Contains(d.Excluded["metal-1"], "IP eth doesn't exist") {
		t.Fatalf("no IP: %+v", d)
	}
	other := ipObj("eth", v1.LBIPPool, func(x *v1.IP) {
		x.Status.BoundTo = []v1.IPHolder{{Holder: "silo/b", UID: "uid-b"}}
		x.Status.Waiting = []v1.IPWaiting{{Holder: "silo/a", UID: "uid-a", Reason: "IP eth is held by silo/b"}}
	})
	if d, _ := Schedule(a, hs, nil, other); !strings.Contains(d.Excluded["metal-1"], "held by silo/b") {
		t.Fatalf("held: %+v", d)
	}
	if d, _ := Schedule(a, hs, nil, ipObj("eth", v1.LBIPPool, nil)); !strings.Contains(d.Excluded["metal-1"], "waiting for IP eth to be bound") {
		t.Fatalf("unbound: %+v", d)
	}
	// Bound, not reserved yet: a host with a free extra address.
	free := ipObj("eth", v1.LBIPPool, boundTo(a))
	if d, _ := Schedule(a, hs, nil, free); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "no free extra address") {
		t.Fatalf("free address: %+v", d)
	}
	// Reserved: the host its address is routed to, only.
	res := ipObj("eth", v1.LBIPPool, func(x *v1.IP) { boundTo(a)(x); x.Status.Host, x.Status.Address = "metal-1", "198.51.100.17" })
	if d, _ := Schedule(a, hs, nil, res); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "routed to metal-1") {
		t.Fatalf("reserved: %+v", d)
	}
	a.Status.Host = "metal-1"
	st, err := ServiceStatus(a, m1, nil, Env{IPs: []*v1.IP{res}})
	if err != nil || st.IP != "eth" || st.LoadBalancerIP != "198.51.100.17" || st.Ports[0].LoadBalancer != "198.51.100.17:30303" || st.EgressIP != "198.51.100.17" || st.EgressNote != "" ||
		len(st.HostAddresses) != 1 || st.HostAddresses[0] != "198.51.100.17" || st.Name != "a.dev.kevaso" {
		t.Fatalf("a: %+v %v", st, err)
	}
	// A plugin's IP: in its region only.
	p := lb("p", "fake-ip")
	pip := ipObj("eth", "fake-ip", func(x *v1.IP) { boundTo(p)(x); x.Status.Region, x.Status.Address = "ca-central", "203.0.113.100" })
	inRegion := host("lin-1", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "ca-central"} })
	away := host("lin-2", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "us-east"} })
	env := Env{IPs: []*v1.IP{pip}, Classes: map[string]Class{"fake-ip": {Plugin: "fake", Reserve: true, SendsFrom: true, Follows: "region"}}}
	if d, _ := ScheduleIn(p, hosts(inRegion, away), nil, env); d.Host != "lin-1" || !strings.Contains(d.Excluded["lin-2"], "in ca-central") {
		t.Fatalf("region: %+v", d)
	}
	env.Classes["fake-ip"] = Class{Plugin: "fake", Follows: "global"}
	if d, _ := ScheduleIn(p, hosts(away), nil, env); d.Host != "lin-2" {
		t.Fatalf("global: %+v", d)
	}
}

// Nothing assumes a host's address, or an IP's, is public: a host with only an internal IP on a
// LAN opens [internal] ports on it, and an ip-pool IP from a private range is handed out, placed
// and sent from like any other.
func TestPrivateAddresses(t *testing.T) {
	lan := host("lan-1", func(h *v1.Host) {
		h.Spec.InternalIP = "192.168.1.10"
		h.Spec.Network.Addresses = []string{"192.168.1.48/30"} // .49 and .50, on the LAN
	})
	hp := exposed("hp", "lan-1", func(s *v1.Silo) {
		s.Spec.Service.Ports[0].HostPort = []string{v1.NetworkInternal}
		s.Spec.Service.Ports[1].HostPort = []string{v1.NetworkInternal}
		s.Spec.Network.Egress.Source = v1.EgressSameAsService
	})
	st, _ := ServiceStatus(hp, lan, nil, Env{})
	if st.Ports[0].Internal != "192.168.1.10:30303" || st.EgressIP != "192.168.1.10" || strings.Join(st.OutsideIPs(), " ") != "192.168.1.10" {
		t.Fatalf("a host port on a LAN-only host: %+v", st)
	}
	s := exposed("p", "", func(s *v1.Silo) {
		s.UID = "uid-p"
		onLB(s, v1.LBIPPool, "lan-ip")
		s.Spec.Network.Egress.Source = v1.EgressSameAsService
	})
	x := ipObj("lan-ip", v1.LBIPPool, func(x *v1.IP) { boundTo(s)(x); x.Status.Host, x.Status.Address = "lan-1", "192.168.1.50" })
	if d, _ := Schedule(s, hosts(lan), nil, x); d.Host != "lan-1" {
		t.Fatalf("a private ip-pool address: %+v", d)
	}
	s.Status.Host = "lan-1"
	st, _ = ServiceStatus(s, lan, nil, Env{IPs: []*v1.IP{x}})
	if st.LoadBalancerIP != "192.168.1.50" || st.EgressIP != "192.168.1.50" || strings.Join(st.OutsideIPs(), " ") != "192.168.1.50" || st.HostAddresses[0] != "192.168.1.50" {
		t.Fatalf("on a private ip-pool address: %+v", st)
	}
}

// The table of design §7.2b: can a silo use the same IP out as in?
func TestEgressTable(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP = "198.51.100.10" })
	classes := map[string]Class{
		"fake-ip": {Plugin: "fake", Reserve: true, SendsFrom: true, Exclusive: true},
		"fake-lb": {Plugin: "fake", NodePorts: true},
	}
	const hostPort, loadBalancer, private = "hostPort", "loadBalancer", "private"
	mk := func(way, class, source string) *v1.Silo {
		s := exposed("n", "metal-1", nil)
		s.UID = "uid-n"
		switch way {
		case loadBalancer:
			onLB(s, class, "")
		case private:
			s.Spec.Service.Ports = []v1.ServicePort{{Port: "rpc"}}
		}
		s.Spec.Network.Egress.Source = source
		return s
	}
	for _, c := range []struct {
		name      string
		silo      *v1.Silo
		in        string
		ip        *v1.IP
		want      string
		note      string // substring; "" means no note
		sameInOut bool
	}{
		{"hostPort, host", mk(hostPort, "", ""), "", nil, "198.51.100.10", "", false},
		{"hostPort, sameAsService", mk(hostPort, "", v1.EgressSameAsService), "", nil, "198.51.100.10", "", false},
		{"ip-pool, sameAsService", mk(loadBalancer, v1.LBIPPool, v1.EgressSameAsService), "198.51.100.17", nil, "198.51.100.17", "", true},
		{"ip-pool, host", mk(loadBalancer, v1.LBIPPool, ""), "198.51.100.17", nil, "198.51.100.10", "sameAsService sends from 198.51.100.17", false},
		{"announced, sameAsService", mk(loadBalancer, "fake-ip", v1.EgressSameAsService), "203.0.113.100",
			ipObj("n", "fake-ip", func(x *v1.IP) { x.Status.Address = "203.0.113.100" }), "203.0.113.100", "", true},
		{"announced, sameAsService, address not yet", mk(loadBalancer, "fake-ip", v1.EgressSameAsService), "", nil, "198.51.100.10", "waiting for IP n", false},
		{"balancer in front, sameAsService: never its address", mk(loadBalancer, "fake-lb", v1.EgressSameAsService), "198.51.100.200", nil,
			"198.51.100.10", "on no host, so nothing can send from it", false},
		{"balancer in front, host", mk(loadBalancer, "fake-lb", ""), "198.51.100.200", nil, "198.51.100.10", "balancer's, on no host", false},
		{"no plugin serves the class: not applied", mk(loadBalancer, "gone-lb", v1.EgressSameAsService), "198.51.100.200", nil,
			"198.51.100.10", "not applied", false},
		{"private", mk(private, "", ""), "", nil, "198.51.100.10", "", false},
	} {
		var held *v1.IP
		if c.ip != nil {
			held = c.ip
		}
		out, note := Egress(c.silo, h, v1.SiloServiceStatus{LoadBalancerIP: c.in}, held, nil, classes)
		if out != c.want || (c.note == "" && note != "") || !strings.Contains(note, c.note) {
			t.Errorf("%s: out %q (%s), want %q (%q)", c.name, out, note, c.want, c.note)
		}
		if c.sameInOut != (out == c.in) {
			t.Errorf("%s: in %s out %s, same %v", c.name, c.in, out, c.sameInOut)
		}
	}
	// pool: its own IP's address out, whatever it's reached on.
	s := mk(loadBalancer, v1.LBIPPool, v1.EgressPool)
	s.Spec.Network.Egress.IP = "out"
	own := ipObj("out", v1.LBIPPool, func(x *v1.IP) { x.Status.Address, x.Status.Host = "198.51.100.18", "metal-1" })
	if out, note := Egress(s, h, v1.SiloServiceStatus{LoadBalancerIP: "198.51.100.17"}, nil, own, classes); out != "198.51.100.18" || !strings.Contains(note, "IP out's own address") {
		t.Errorf("pool: %s %s", out, note)
	}
}

func TestServiceStatusHostPort(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP = "198.51.100.10" })
	s := exposed("n", "metal-1", func(s *v1.Silo) { s.Spec.Network.Egress.Source = v1.EgressSameAsService })
	st, _ := ServiceStatus(s, h, nil, Env{})
	if st.Ports[0].External != "198.51.100.10:30303" || st.EgressIP != "198.51.100.10" || len(st.HostAddresses) != 0 || st.LoadBalancerIP != "" {
		t.Fatalf("%+v", st)
	}
	plain := silo("plain")
	if st, _ := ServiceStatus(plain, h, nil, Env{}); len(st.OutsideIPs()) != 0 || st.EgressIP != "198.51.100.10" {
		t.Fatalf("private: %+v", st)
	}
	if st, _ := ServiceStatus(plain, host("home", func(h *v1.Host) { h.Spec.Network.BehindNAT = true }), nil, Env{}); st.EgressIP != "" {
		t.Fatalf("behind NAT there's no known egress address: %+v", st)
	}
}
