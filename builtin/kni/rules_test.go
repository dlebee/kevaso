package kni

import (
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

var (
	a = netip.MustParseAddr
)

func p2p() v1.SiloSpec {
	return v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{
			{Port: "p2p", HostPort: []string{v1.NetworkExternal}}, {Port: "disc", HostPort: []string{v1.NetworkExternal}}, {Port: "rpc"}}},
		Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressSameAsService}}}
}

// opens is a silo that declares one TCP port and opens it as sp says.
func opens(number int, sp v1.ServicePort) v1.SiloSpec {
	sp.Port = "web"
	return v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: number}}, Service: &v1.SiloService{Ports: []v1.ServicePort{sp}}}
}

// Rule generation per case (design §7.0): a port opens on exactly the addresses it asks for, at
// its as number, from its sources; a declared port nothing opens, or a silo without a service, has
// no rule at all.
func TestOutsideRulesPerCase(t *testing.T) {
	const ip = "10.64.2.2"
	internalOnly := host()
	internalOnly.ExternalIP = netip.Addr{}
	cases := []struct {
		name     string
		h        Host
		spec     v1.SiloSpec
		lb       netip.Addr
		want     []string
		wantNone []string
	}{
		{"external only, as 443", host(), opens(8443, v1.ServicePort{HostPort: []string{"external"}, As: 443}), netip.Addr{},
			[]string{"ip daddr 198.51.100.10 tcp dport 443 dnat ip to 10.64.2.2:8443",
				`oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 8443 ct original ip daddr 198.51.100.10 ct status dnat accept`},
			[]string{"ip daddr 10.0.0.5", "dport 8443 dnat"}},
		{"internal only", host(), opens(9090, v1.ServicePort{HostPort: []string{"internal"}}), netip.Addr{},
			[]string{"ip daddr 10.0.0.5 tcp dport 9090 dnat ip to 10.64.2.2:9090"},
			[]string{"ip daddr 198.51.100.10"}},
		{"both", host(), opens(9229, v1.ServicePort{HostPort: []string{"internal", "external"}}), netip.Addr{},
			[]string{"ip daddr { 10.0.0.5, 198.51.100.10 } tcp dport 9229 dnat ip to 10.64.2.2:9229"}, nil},
		{"external asked, host has none: nothing", internalOnly, opens(443, v1.ServicePort{HostPort: []string{"external"}}), netip.Addr{},
			nil, []string{"dnat ip to 10.64.2.2"}},
		{"sources", host(), opens(3000, v1.ServicePort{HostPort: []string{"internal"}, Sources: []string{"10.0.0.0/24", "192.0.2.7"}}), netip.Addr{},
			[]string{`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr { 10.0.0.0/24, 192.0.2.7 } tcp dport 3000 ct original ip daddr 10.0.0.5 ct status dnat accept`}, nil},
		{"allowFrom only: nothing outside", host(), opens(8080, v1.ServicePort{AllowFrom: []string{"worker"}}), netip.Addr{},
			nil, []string{"dnat ip to 10.64.2.2"}},
		{"declared, not opened", host(), v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: 8080}}, Service: &v1.SiloService{}}, netip.Addr{},
			nil, []string{"dport 8080"}},
		{"no service", host(), v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: 8080}}}, netip.Addr{},
			nil, []string{"dport 8080"}},
		{"ip-pool load balancer, as 30000", host(), func() v1.SiloSpec {
			s := opens(30303, v1.ServicePort{LoadBalancer: true, As: 30000})
			s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool}
			return s
		}(), a("198.51.100.17"),
			[]string{"ip daddr 198.51.100.17 tcp dport 30000 dnat ip to 10.64.2.2:30303"},
			[]string{"ip daddr 198.51.100.10", "ip daddr 10.0.0.5"}},
		{"on the host and the load balancer", host(), func() v1.SiloSpec {
			s := opens(53, v1.ServicePort{LoadBalancer: true, HostPort: []string{"internal"}})
			s.Ports[0].Protocol = "UDP"
			s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: v1.LBIPPool}
			return s
		}(), a("198.51.100.17"),
			[]string{"ip daddr { 10.0.0.5, 198.51.100.17 } udp dport 53 dnat ip to 10.64.2.2:53"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := c.h
			h.Local = []Silo{{Key: "dev/api", IP: a(ip), Spec: c.spec, LoadBalancerIP: c.lb}}
			r := Rules(h)
			has(t, r, c.want...)
			hasNot(t, r, c.wantNone...)
		})
	}
}

func host(local ...Silo) Host {
	return Host{Bridge: "kvbr0", Subnet: netip.MustParsePrefix("10.64.2.0/24"), Gateway: a("10.64.2.1"), InternalIP: a("10.0.0.5"), ExternalIP: a("198.51.100.10"), Local: local}
}

func has(t *testing.T, rules string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(rules, w) {
			t.Errorf("missing %q in:\n%s", w, rules)
		}
	}
}

func hasNot(t *testing.T, rules string, bad ...string) {
	t.Helper()
	for _, w := range bad {
		if strings.Contains(rules, w) {
			t.Errorf("unexpected %q in:\n%s", w, rules)
		}
	}
}

// Example 03's P2P node: TCP+UDP 30303 public on the host's IP, rpc private, outbound from the
// same IP.
func TestHostPortAndSameAsService(t *testing.T) {
	s := Silo{Key: "web3/eth-node", IP: a("10.64.2.2"), Tap: "kvt0011223344", Spec: p2p(), EgressIP: a("198.51.100.10")}
	r := Rules(host(s))
	has(t, r,
		"ip daddr 198.51.100.10 tcp dport 30303 dnat ip to 10.64.2.2:30303",
		"ip daddr 198.51.100.10 udp dport 30303 dnat ip to 10.64.2.2:30303",
		`oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 30303 ct original ip daddr 198.51.100.10 ct status dnat accept`,
		`ip saddr 10.64.2.2 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } oifname != "kvbr0" snat ip to 198.51.100.10`,
		`iifname "kvt0011223344" ip saddr != 10.64.2.2 drop`,
		`iifname "kvt0011223344" arp saddr ip != 10.64.2.2 drop`,
		"ether type arp accept",
		`oifname "kvbr0" drop`, // everything else to silos
	)
	hasNot(t, r, "dport 8545") // rpc stays private
	// SNAT before the general masquerade.
	if strings.Index(r, "snat ip to") > strings.Index(r, "masquerade") {
		t.Error("the silo's SNAT comes after the masquerade and would never match")
	}
}

// Example 06: two silos, both 30303, each on its own ip-pool IP, in and out.
func TestPoolAddresses(t *testing.T) {
	spec := v1.SiloSpec{Ports: []v1.SiloPort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "p2p", LoadBalancer: true}, {Port: "disc", LoadBalancer: true}},
			LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool}},
		Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressSameAsService}}}
	r := Rules(host(
		Silo{Key: "web3/eth-node-a", IP: a("10.64.2.2"), Spec: spec, LoadBalancerIP: a("198.51.100.17"), EgressIP: a("198.51.100.17")},
		Silo{Key: "web3/eth-node-b", IP: a("10.64.2.3"), Spec: spec, LoadBalancerIP: a("198.51.100.18"), EgressIP: a("198.51.100.18")},
	))
	has(t, r,
		"ip daddr 198.51.100.17 tcp dport 30303 dnat ip to 10.64.2.2:30303",
		"ip daddr 198.51.100.18 tcp dport 30303 dnat ip to 10.64.2.3:30303",
		"ip saddr 10.64.2.2 ip daddr", "snat ip to 198.51.100.17",
		"ip saddr 10.64.2.3 ip daddr", "snat ip to 198.51.100.18",
	)
}

// The address out (design §7.2b), as the host's rules write it from the silo's status: an
// announced shared IP and an ip-pool IP send from themselves; behind a balancer (node ports) the
// silo sends from the host's address, and nothing ever sends from the balancer's.
func TestEgressCases(t *testing.T) {
	lb := func(class string) v1.SiloSpec {
		s := opens(30303, v1.ServicePort{LoadBalancer: true})
		s.Service.LoadBalancer = &v1.LoadBalancerSpec{Class: class}
		s.Network.Egress.Source = v1.EgressSameAsService
		return s
	}
	shared := Silo{Key: "web3/shared", IP: a("10.64.2.2"), Spec: lb("linode-shared-ip"), LoadBalancerIP: a("203.0.113.100"), EgressIP: a("203.0.113.100")}
	pooled := Silo{Key: "web3/pooled", IP: a("10.64.2.3"), Spec: lb(v1.LBIPPool), LoadBalancerIP: a("198.51.100.17"), EgressIP: a("198.51.100.17")}
	behind := Silo{Key: "web3/behind", IP: a("10.64.2.4"), Spec: lb("linode-nodebalancer"), EgressIP: a("198.51.100.10"),
		NodePorts: []v1.NodePort{{Name: "web", Port: 30303, NodePort: 30000}}, SourceRanges: []string{"192.168.255.0/24"}}
	plain := Silo{Key: "web3/plain", IP: a("10.64.2.5")}
	r := Rules(host(shared, pooled, behind, plain))
	has(t, r,
		"ip saddr 10.64.2.2 ip daddr", "snat ip to 203.0.113.100",
		"ip saddr 10.64.2.3 ip daddr", "snat ip to 198.51.100.17",
		"ip saddr 10.64.2.4 ip daddr", "snat ip to 198.51.100.10",
	)
	for _, l := range strings.Split(r, "\n") {
		if strings.Contains(l, "ip saddr 10.64.2.5 ") && strings.Contains(l, "snat") {
			t.Errorf("a silo with egress.source host gets the host's default, no snat of its own: %s", l)
		}
		if strings.Contains(l, "ip saddr 10.64.2.4 ") && strings.Contains(l, "snat") && !strings.Contains(l, "198.51.100.10") {
			t.Errorf("behind a balancer, out is the host's address: %s", l)
		}
	}
}

// allowFrom: same host (bridged) and across the mesh (routed), port by port; the source must be
// running. An Ingress's path (Paths) opens the same way.
func TestAllowFrom(t *testing.T) {
	api := Silo{Key: "payments/api", IP: a("10.64.2.2"), Spec: v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "http", Port: 8080}, {Name: "admin", Port: 9090}, {Name: "debug", Port: 9229}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{
			{Port: "http", AllowFrom: []string{"worker", "research/crawler", "ghost"}},
			{Port: "admin", AllowFrom: []string{"research/crawler"}}, {Port: "debug"}}},
	}, Paths: map[string][]string{"debug": {"kevaso-system/ingress-public"}}}
	worker := Silo{Key: "payments/worker", IP: a("10.64.2.5")}   // same host
	crawler := Silo{Key: "research/crawler", IP: a("10.64.7.9")} // another host
	h := host(api, worker)
	ingress := Silo{Key: "kevaso-system/ingress-public", IP: a("10.64.4.4")}
	h.All = []Silo{api, worker, crawler, ingress, {Key: "payments/ghost"}} // ghost has no address: not running
	r := Rules(h)
	has(t, r,
		"ip saddr 10.64.2.5 ip daddr 10.64.2.2 tcp dport 8080 accept",                 // worker → http, bridged
		`oifname "kvbr0" ip saddr 10.64.7.9 ip daddr 10.64.2.2 tcp dport 8080 accept`, // crawler → http and admin, routed
		`oifname "kvbr0" ip saddr 10.64.7.9 ip daddr 10.64.2.2 tcp dport 9090 accept`,
		`oifname "kvbr0" ip saddr 10.64.4.4 ip daddr 10.64.2.2 tcp dport 9229 accept`, // the ingress's path
		`iifname "kvt*" oifname "kvt*" drop`,
	)
	hasNot(t, r, "ip saddr 10.64.2.5 ip daddr 10.64.2.2 tcp dport 9090", // worker only got http
		"ip saddr 10.64.4.4 ip daddr 10.64.2.2 tcp dport 8080") // the ingress only its path
	// The bridged rule lives in the bridge table, before its default drop.
	_, bt, _ := strings.Cut(r, "table bridge kevaso {")
	if i, j := strings.Index(bt, "ip saddr 10.64.2.5"), strings.Index(bt, `oifname "kvt*" drop`); i < 0 || i > j {
		t.Error("the same-host allow isn't in the bridge table before its drop")
	}
}

func TestDefaultsAndIsolation(t *testing.T) {
	r := Rules(host(Silo{Key: "dev/plain", IP: a("10.64.2.2")}))
	has(t, r,
		`iifname "kvbr0" ip daddr { 10.62.0.0/16, 10.63.0.0/16 } drop`, // no mesh host addresses
		`iifname "kvbr0" ip daddr 10.64.2.1 udp dport 53 accept`,       // DNS on the gateway
		`iifname "kvbr0" drop`, // nothing else of the host
		"ip saddr 10.64.2.0/24 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } oifname != \"kvbr0\" masquerade",
		"table inet kevaso_nat\ndelete table inet kevaso_nat", // old tables cleaned up
	)
	hasNot(t, r, "dnat ip to", "snat ip to")
	if Rules(host(Silo{Key: "dev/plain", IP: a("10.64.2.2")})) != r {
		t.Error("not deterministic")
	}
}

// Default-deny egress: a silo reaches outside the cluster only what its grants open (example 03's
// p2p-anywhere), while other silos over the mesh and replies always pass.
func TestEgressGrants(t *testing.T) {
	parse := func(r v1.EgressRule) v1.ParsedEgress {
		e, err := r.Parse()
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	node := Silo{Key: "web3/eth-node", IP: a("10.64.2.2"), Egress: []v1.ParsedEgress{
		parse(v1.EgressRule{To: "0.0.0.0/0", Ports: []string{"30303"}, Protocols: []string{"tcp", "udp"}}),
		parse(v1.EgressRule{To: "203.0.113.0/24", Ports: []string{"8000-8100", "9000"}}),
		parse(v1.EgressRule{To: "198.51.100.7"}),
		parse(v1.EgressRule{To: "api.github.com"}), // a name: the gate's job, not a firewall rule
	}}
	plain := Silo{Key: "web3/plain", IP: a("10.64.2.3")}
	r := Rules(host(node, plain))
	_, fwd, _ := strings.Cut(r, "chain forward {")
	fwd, _, _ = strings.Cut(fwd, "\n  }")
	has(t, fwd,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 0.0.0.0/0 tcp dport 30303 accept`,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 0.0.0.0/0 udp dport 30303 accept`,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 203.0.113.0/24 tcp dport { 8000-8100, 9000 } accept`,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 198.51.100.7/32 meta l4proto tcp accept`,
		`iifname "kvbr0" ct state established,related accept`,
		`iifname "kvbr0" ip daddr 10.64.0.0/16 accept`,
	)
	hasNot(t, fwd, "10.64.2.3 ip daddr", "github")
	// Order: the mesh-host drop first, the default drop last.
	if i, j := strings.Index(fwd, "ip daddr { 10.62.0.0/16, 10.63.0.0/16 } drop"), strings.Index(fwd, "0.0.0.0/0 tcp dport 30303"); i < 0 || i > j {
		t.Error("a grant comes before the mesh-host drop: 0.0.0.0/0 would open the mesh")
	}
	lines := strings.Split(strings.TrimSpace(fwd), "\n")
	if last := strings.TrimSpace(lines[len(lines)-1]); last != `iifname "kvbr0" drop` {
		t.Errorf("forward chain ends with %q, want the default-deny drop", last)
	}
}

// Grants by host name and injected secrets: the silo's TLS to outside the cluster goes to the gate.
func TestGateRedirect(t *testing.T) {
	s := Silo{Key: "dev/claude-1", IP: a("10.64.2.2"), GatePorts: []v1.PortRange{{From: 443, To: 443}, {From: 8443, To: 8443}}}
	plain := Silo{Key: "dev/plain", IP: a("10.64.2.3")}
	h := host(s, plain)
	h.GatePort = 15001
	r := Rules(h)
	has(t, r,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr != { 10.64.0.0/16, 10.65.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } tcp dport { 443, 8443 } redirect to :15001`,
		`iifname "kvbr0" ip daddr 10.64.2.1 tcp dport 15001 accept`,
	)
	hasNot(t, r, "ip saddr 10.64.2.3 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } tcp dport")
	// The gate's port opens only on the input chain, before its drop.
	_, in, _ := strings.Cut(r, "chain input {")
	if i, j := strings.Index(in, "dport 15001 accept"), strings.Index(in, `iifname "kvbr0" drop`); i < 0 || i > j {
		t.Error("gate port not accepted before the input drop")
	}
	h.GatePort = 0
	hasNot(t, Rules(h), "redirect", "15001")
}

// A plugin's load balancer (a NodeBalancer) reaches the silo through node ports, from its own
// addresses only; nothing opens on the host's public address.
func TestNodePortRules(t *testing.T) {
	spec := v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: 80}, {Name: "dns", Port: 53, Protocol: "UDP"}},
		Service: &v1.SiloService{LoadBalancer: &v1.LoadBalancerSpec{Class: "linode-nodebalancer"},
			Ports: []v1.ServicePort{{Port: "web", LoadBalancer: true}, {Port: "dns", LoadBalancer: true}}}}
	r := Rules(host(Silo{Key: "dev/web", IP: a("10.64.2.5"), Spec: spec,
		NodePorts:    []v1.NodePort{{Name: "web", Port: 80, NodePort: 30000}, {Name: "dns", Port: 53, NodePort: 30001}},
		SourceRanges: []string{"192.168.255.0/24"}}))
	has(t, r,
		"ip saddr 192.168.255.0/24 tcp dport 30000 dnat ip to 10.64.2.5:80",
		"ip saddr 192.168.255.0/24 udp dport 30001 dnat ip to 10.64.2.5:53",
		`oifname "kvbr0" ip daddr 10.64.2.5 ip saddr 192.168.255.0/24 tcp dport 80 ct status dnat accept`)
	hasNot(t, r, "ip daddr 198.51.100.10")
}

func TestServiceRules(t *testing.T) {
	h := host(Silo{Key: "web3/rpc-0", IP: a("10.64.2.2"), Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "rpc", Port: 8545}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "rpc", AllowFrom: []string{"client"}}}}}})
	h.All = []Silo{{Key: "web3/client", IP: a("10.64.2.9")}}
	h.Local = append(h.Local, Silo{Key: "web3/client", IP: a("10.64.2.9")})
	h.Services = []Service{{Key: "web3/rpc", ClusterIP: a("10.65.0.1"), SourceRanges: []string{"192.168.255.0/24"},
		Ports: []ServicePort{{Proto: "tcp", Port: 8545, NodePort: 32000, Targets: []Target{
			{IP: a("10.64.2.2"), Port: 8545, Local: true}, {IP: a("10.64.3.2"), Port: 8545}}}}}}
	r := Rules(h)
	has(t, r,
		// The virtual IP from this host's silos, to any endpoint, at random.
		`iifname "kvbr0" ip daddr 10.65.0.1 tcp dport 8545 dnat ip to numgen random mod 2 map { 0 : 10.64.2.2 . 8545, 1 : 10.64.3.2 . 8545 }`,
		// The node port from the load balancer: only this host's endpoints (client address kept).
		`ip saddr 192.168.255.0/24 tcp dport 32000 dnat ip to 10.64.2.2:8545`,
		`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 192.168.255.0/24 tcp dport 8545 ct status dnat accept`,
		// A same-host client reaching it through the virtual IP is routed: allowFrom still decides.
		`oifname "kvbr0" ip saddr 10.64.2.9 ip daddr 10.64.2.2 tcp dport 8545 ct status dnat accept`,
		// …and masqueraded, so the reply comes back through the translation.
		`ip saddr 10.64.2.0/24 ip daddr 10.64.2.0/24 oifname "kvbr0" ct status dnat masquerade`,
	)
	// No endpoints: no rule (a connection is refused rather than sent nowhere).
	h.Services[0].Ports[0].Targets = nil
	hasNot(t, Rules(h), "10.65.0.1")
}
