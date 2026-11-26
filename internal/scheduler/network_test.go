package scheduler

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// onWorker are the services opening ports on the worker's address on each of nets (one HostPort
// service per network, named after it), or one Internal service when nets is empty.
func onWorker(nets []string, ports ...v1.ServicePort) []v1.SiloService {
	if len(nets) == 0 {
		return []v1.SiloService{{Ports: ports}}
	}
	var out []v1.SiloService
	for _, n := range nets {
		out = append(out, v1.SiloService{Name: "on-" + n, Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: n}, Ports: ports})
	}
	return out
}

// exposed is a P2P node: p2p and disc (30303 TCP and UDP) on its host's external IP, rpc only
// on its silo IP.
func exposed(name, host string, f func(*v1.Silo)) *v1.Silo {
	s := silo(name)
	s.Spec.Ports = []v1.SiloPort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}}
	s.Spec.Services = []v1.SiloService{
		{Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "p2p"}, {Port: "disc"}}},
		{Name: name + "-rpc", Ports: []v1.ServicePort{{Port: "rpc"}}},
	}
	s.Status.Host = host
	if f != nil {
		f(s)
	}
	return s
}

func ipObj(name, typ string, f func(*v1.IP)) *v1.IP {
	x := &v1.IP{}
	x.Name, x.Namespace, x.UID, x.Spec.Type = name, "dev", "ip-"+name, typ
	if f != nil {
		f(x)
	}
	return x
}

func boundTo(s *v1.Silo) func(*v1.IP) {
	return func(x *v1.IP) { x.Status.Holder = &v1.IPHolder{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID} }
}

// onIP makes s's first service arrive on the IP named ip (hostPort.ip).
func onIP(s *v1.Silo, ip string) {
	s.Spec.Services[0].Type, s.Spec.Services[0].HostPort = v1.ServiceHostPort, &v1.HostPortSource{IP: ip}
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
		s.Spec.Services = onWorker(nets, v1.ServicePort{Port: "https", As: as})
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
// addresses it opens on, at its as number; one entry per service it's in.
func TestPortStatus(t *testing.T) {
	h := host("ovh-1", func(h *v1.Host) { h.Spec.InternalIP, h.Spec.ExternalIP = "10.0.0.5", "51.38.10.20" })
	s := silo("api-blue")
	s.Status.Host, s.Status.SiloIP = "ovh-1", "10.64.2.7"
	s.Spec.Ports = []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "https", Port: 8443}, {Name: "metrics", Port: 9090}, {Name: "debug", Port: 9229}, {Name: "unused", Port: 1}}
	s.Spec.Services = []v1.SiloService{
		{Name: "api", Ports: []v1.ServicePort{{Port: "http", AllowFrom: []string{"nginx-public"}}}},
		{Name: "api-ext", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "https", As: 443}, {Port: "debug"}}},
		{Name: "api-int", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{Worker: v1.NetworkInternal},
			Ports: []v1.ServicePort{{Port: "metrics", Sources: []string{"10.0.0.0/24"}}, {Port: "debug"}}},
	}
	st, err := ServiceStatus(s, h, nil, Env{})
	want := []v1.ServicePortStatus{
		{Port: "http", Mesh: "10.64.2.7:8080"},
		{Port: "https", Mesh: "10.64.2.7:8443", External: "51.38.10.20:443"},
		{Port: "debug", Mesh: "10.64.2.7:9229", External: "51.38.10.20:9229"},
		{Port: "metrics", Mesh: "10.64.2.7:9090", Internal: "10.0.0.5:9090"},
		{Port: "debug", Mesh: "10.64.2.7:9229", Internal: "10.0.0.5:9229"},
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
	// An unnamed first service: the silo's name.
	s.Spec.Services[0].Name = ""
	if st, _ := ServiceStatus(s, h, nil, Env{}); st.Name != "api-blue.dev.kevaso" {
		t.Errorf("unnamed: %s", st.Name)
	}
	// No service: no name, nothing reachable; its traffic out still has an address.
	s.Spec.Services = nil
	if st, _ := ServiceStatus(s, h, nil, Env{}); st.Name != "" || len(st.Ports) != 0 || st.EgressIP != "51.38.10.20" {
		t.Errorf("no service: %+v", st)
	}
}

// An IP is held before its silo is placed; a Host IP goes only on the host with its address, a
// Provider IP only on that provider's machines in its region.
func TestIPScheduling(t *testing.T) {
	m1 := host("metal-1", func(h *v1.Host) {
		h.Spec.ExternalIP = "198.51.100.10"
		h.Spec.Addresses = []v1.HostAddress{{Name: "m1-a", Kind: v1.NetworkExternal, Address: "198.51.100.17"}}
	})
	m2 := host("metal-2")
	hs := hosts(m1, m2)
	a := exposed("a", "", func(s *v1.Silo) {
		s.UID = "uid-a"
		onIP(s, "eth")
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "eth"}
	})
	// Not made yet, held by another, not bound yet: nowhere.
	if d, _ := Schedule(a, hs, nil); !strings.Contains(d.Excluded["metal-1"], "IP eth doesn't exist") {
		t.Fatalf("no IP: %+v", d)
	}
	other := ipObj("eth", v1.IPTypeHost, func(x *v1.IP) {
		x.Spec.HostAddress = "m1-a"
		x.Status.Holder = &v1.IPHolder{Holder: "silo/b", UID: "uid-b"}
		x.Status.Waiting = []v1.IPWaiting{{Holder: "silo/a", UID: "uid-a", Reason: "IP eth is held by silo/b"}}
	})
	if d, _ := Schedule(a, hs, nil, other); d.Host != "" || !strings.Contains(d.Excluded["metal-1"], "held by silo/b") {
		t.Fatalf("held: %+v", d)
	}
	if d, _ := Schedule(a, hs, nil, ipObj("eth", v1.IPTypeHost, func(x *v1.IP) { x.Spec.HostAddress = "m1-a" })); !strings.Contains(d.Excluded["metal-1"], "waiting for IP eth to be bound") {
		t.Fatalf("unbound: %+v", d)
	}
	// Held, a Host IP: the host with that address, found by name before the IP says where.
	byName := ipObj("eth", v1.IPTypeHost, func(x *v1.IP) { boundTo(a)(x); x.Spec.HostAddress = "m1-a" })
	if d, _ := Schedule(a, hs, nil, byName); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "is host metal-1's address") {
		t.Fatalf("by name: %+v", d)
	}
	nowhere := ipObj("eth", v1.IPTypeHost, func(x *v1.IP) { boundTo(a)(x); x.Spec.HostAddress = "gone" })
	if d, _ := Schedule(a, hs, nil, nowhere); d.Host != "" || !strings.Contains(d.Excluded["metal-1"], "no host has address gone") {
		t.Fatalf("no such address: %+v", d)
	}
	res := ipObj("eth", v1.IPTypeHost, func(x *v1.IP) {
		boundTo(a)(x)
		x.Spec.HostAddress = "m1-a"
		x.Status.Host, x.Status.Address = "metal-1", "198.51.100.17"
	})
	if d, _ := Schedule(a, hs, nil, res); d.Host != "metal-1" || !strings.Contains(d.Excluded["metal-2"], "is host metal-1's address") {
		t.Fatalf("reserved: %+v", d)
	}
	a.Status.Host = "metal-1"
	st, err := ServiceStatus(a, m1, nil, Env{IPs: []*v1.IP{res}})
	if err != nil || st.EgressIP != "198.51.100.17" || st.EgressNote != "" || len(st.HostAddresses) != 1 || st.HostAddresses[0] != "198.51.100.17" || st.Name != "a.dev.kevaso" {
		t.Fatalf("a: %+v %v", st, err)
	}
	// Not on the host it's placed on (yet): no address for it there, out is the worker's.
	st, _ = ServiceStatus(a, m2, nil, Env{IPs: []*v1.IP{res}})
	if len(st.HostAddresses) != 0 || st.EgressIP != "" || !strings.Contains(st.EgressNote, "waiting for IP eth") {
		t.Fatalf("a elsewhere: %+v", st)
	}
	// A Provider IP: that provider's machines in its region only.
	p := exposed("p", "", func(s *v1.Silo) { s.UID = "uid-p"; onIP(s, "eth") })
	pip := ipObj("eth", v1.IPTypeProvider, func(x *v1.IP) {
		boundTo(p)(x)
		x.Spec.Provider, x.Spec.Region = "fake", "ca-central"
		x.Status.Region, x.Status.Address = "ca-central", "203.0.113.100"
	})
	inRegion := host("lin-1", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "ca-central"} })
	away := host("lin-2", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "fake", Region: "us-east"} })
	elsewhere := host("het-1", func(h *v1.Host) { h.Status.Provider = &v1.HostProvider{Name: "hetzner", Region: "ca-central"} })
	if d, _ := Schedule(p, hosts(inRegion, away, elsewhere, m2), nil, pip); d.Host != "lin-1" ||
		!strings.Contains(d.Excluded["lin-2"], "is fake's, in ca-central") || !strings.Contains(d.Excluded["het-1"], "is fake's") || !strings.Contains(d.Excluded["metal-2"], "is fake's") {
		t.Fatalf("region: %+v", d)
	}
	// Two IPs: both rules.
	two := exposed("t", "", func(s *v1.Silo) {
		s.UID = "uid-t"
		onIP(s, "eth")
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "out"}
	})
	out := ipObj("out", v1.IPTypeHost, func(x *v1.IP) { boundTo(two)(x); x.Spec.HostAddress = "m1-a" })
	if d, _ := Schedule(two, hs, nil, ipObj("eth", v1.IPTypeHost, func(x *v1.IP) { boundTo(two)(x); x.Spec.HostAddress = "m1-a" }), out); d.Host != "metal-1" {
		t.Fatalf("two IPs: %+v", d)
	}
}

// Nothing assumes a host's address, or an IP's, is public: a host with only an internal IP on a
// LAN opens worker-internal ports on it, and a Host IP from a private range is placed and sent
// from like any other.
func TestPrivateAddresses(t *testing.T) {
	lan := host("lan-1", func(h *v1.Host) {
		h.Spec.InternalIP = "192.168.1.10"
		h.Spec.Addresses = []v1.HostAddress{{Name: "lan-a", Kind: v1.NetworkInternal, Address: "192.168.1.50"}}
	})
	hp := exposed("hp", "lan-1", func(s *v1.Silo) {
		s.Spec.Services[0].HostPort = &v1.HostPortSource{Worker: v1.NetworkInternal}
	})
	st, _ := ServiceStatus(hp, lan, nil, Env{})
	if st.Ports[0].Internal != "192.168.1.10:30303" || st.EgressIP != "192.168.1.10" || strings.Join(st.OutsideIPs(), " ") != "192.168.1.10" {
		t.Fatalf("a host port on a LAN-only host: %+v", st)
	}
	s := exposed("p", "", func(s *v1.Silo) {
		s.UID = "uid-p"
		onIP(s, "lan-ip")
		s.Spec.Network.Egress.Source = &v1.EgressSource{IP: "lan-ip"}
	})
	x := ipObj("lan-ip", v1.IPTypeHost, func(x *v1.IP) {
		boundTo(s)(x)
		x.Spec.HostAddress = "lan-a"
		x.Status.Host, x.Status.Address = "lan-1", "192.168.1.50"
	})
	if d, _ := Schedule(s, hosts(lan), nil, x); d.Host != "lan-1" {
		t.Fatalf("a private Host IP: %+v", d)
	}
	s.Status.Host = "lan-1"
	st, _ = ServiceStatus(s, lan, nil, Env{IPs: []*v1.IP{x}})
	if st.EgressIP != "192.168.1.50" || len(st.HostAddresses) != 1 || st.HostAddresses[0] != "192.168.1.50" {
		t.Fatalf("on a private Host IP: %+v", st)
	}
}

// Where a silo's traffic comes from (design §7.2b): the worker's own address unless
// egress.source names one it can send from.
func TestEgressTable(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP = "198.51.100.10" })
	mk := func(src *v1.EgressSource) *v1.Silo {
		s := exposed("n", "metal-1", nil)
		s.UID = "uid-n"
		s.Spec.Network.Egress.Source = src
		return s
	}
	onH := ipObj("mail", v1.IPTypeHost, func(x *v1.IP) { x.Status.Address, x.Status.Host = "198.51.100.17", "metal-1" })
	away := ipObj("mail", v1.IPTypeHost, func(x *v1.IP) { x.Status.Address, x.Status.Host = "198.51.100.18", "metal-2" })
	for _, c := range []struct {
		name string
		silo *v1.Silo
		in   string // its load-balancer address
		ip   *v1.IP
		want string
		note string // substring; "" means no note
	}{
		{"no source: the worker's", mk(nil), "", nil, "198.51.100.10", ""},
		{"source ip, on the host", mk(&v1.EgressSource{IP: "mail"}), "", onH, "198.51.100.17", ""},
		{"source ip, not held yet", mk(&v1.EgressSource{IP: "mail"}), "", nil, "198.51.100.10", "waiting for IP mail's address"},
		{"source ip, no address yet", mk(&v1.EgressSource{IP: "mail"}), "", ipObj("mail", v1.IPTypeProvider, nil), "198.51.100.10", "waiting for IP mail's address"},
		{"source ip, on another host", mk(&v1.EgressSource{IP: "mail"}), "", away, "198.51.100.10", "waiting for IP mail's address"},
		{"source own: not applied yet", mk(&v1.EgressSource{Own: true}), "", nil, "198.51.100.10", "isn't applied yet"},
		{"a balancer in front, no source: says so", mk(nil), "198.51.100.200", nil, "198.51.100.10", "no egress.source"},
		{"a balancer in front on the worker's address: no note", mk(nil), "198.51.100.10", nil, "198.51.100.10", ""},
	} {
		out, note := Egress(c.silo, h, v1.SiloServiceStatus{LoadBalancerIP: c.in}, c.ip)
		if out != c.want || (c.note == "" && note != "") || !strings.Contains(note, c.note) {
			t.Errorf("%s: out %q (%s), want %q (%q)", c.name, out, note, c.want, c.note)
		}
	}
	// Behind NAT, the worker's own address out isn't known.
	nat := host("home", func(h *v1.Host) { h.Spec.ExternalIP, h.Spec.Network.BehindNAT = "", true })
	if out, _ := Egress(mk(nil), nat, v1.SiloServiceStatus{}, nil); out != "" {
		t.Errorf("behind NAT: %q", out)
	}
}

func TestServiceStatusHostPort(t *testing.T) {
	h := host("metal-1", func(h *v1.Host) { h.Spec.ExternalIP = "198.51.100.10" })
	s := exposed("n", "metal-1", nil)
	st, _ := ServiceStatus(s, h, nil, Env{})
	if st.Ports[0].External != "198.51.100.10:30303" || st.EgressIP != "198.51.100.10" || len(st.HostAddresses) != 0 || st.LoadBalancerIP != "" || st.Name != "n.dev.kevaso" {
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
