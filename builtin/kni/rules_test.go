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
	return v1.SiloSpec{Service: &v1.Service{
		Ports:    []v1.ServicePort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}, {Name: "rpc", Port: 8545}},
		Expose:   v1.ExposeHostPort,
		HostPort: &v1.HostPortSpec{Ports: []string{"p2p", "disc"}},
	}, Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressSameAsService}}}
}

func host(local ...Silo) Host {
	return Host{Bridge: "kvbr0", Subnet: netip.MustParsePrefix("10.64.2.0/24"), Gateway: a("10.64.2.1"), Address: a("198.51.100.10"), Local: local}
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
	s := Silo{Key: "web3/eth-node", IP: a("10.64.2.2"), Tap: "kvt0011223344", Spec: p2p(), PublicIP: a("198.51.100.10"), EgressIP: a("198.51.100.10")}
	r := Rules(host(s))
	has(t, r,
		"ip daddr 198.51.100.10 tcp dport 30303 dnat ip to 10.64.2.2:30303",
		"ip daddr 198.51.100.10 udp dport 30303 dnat ip to 10.64.2.2:30303",
		`oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 30303 ct status dnat accept`,
		`ip saddr 10.64.2.2 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } oifname != "kvbr0" snat ip to 198.51.100.10`,
		`iifname "kvt0011223344" ip saddr != 10.64.2.2 drop`,
		`oifname "kvbr0" drop`, // everything else to silos
	)
	hasNot(t, r, "dport 8545") // rpc stays private
	// SNAT before the general masquerade.
	if strings.Index(r, "snat ip to") > strings.Index(r, "masquerade") {
		t.Error("the silo's SNAT comes after the masquerade and would never match")
	}
}

// Example 03's dashboard: only the office range.
func TestHostPortAllowFromCIDRs(t *testing.T) {
	spec := v1.SiloSpec{Service: &v1.Service{Ports: []v1.ServicePort{{Name: "web", Port: 3000}}, Expose: v1.ExposeHostPort,
		HostPort: &v1.HostPortSpec{Ports: []string{"web"}, AllowFrom: []string{"203.0.113.0/24"}}}}
	r := Rules(host(Silo{Key: "ops/metrics", IP: a("10.64.2.3"), Spec: spec, PublicIP: a("198.51.100.10")}))
	has(t, r, `oifname "kvbr0" ip daddr 10.64.2.3 ip saddr 203.0.113.0/24 tcp dport 3000 ct status dnat accept`)
	spec.Service.HostPort.AllowFrom = []string{"203.0.113.0/24", "192.0.2.7"}
	r = Rules(host(Silo{Key: "ops/metrics", IP: a("10.64.2.3"), Spec: spec, PublicIP: a("198.51.100.10")}))
	has(t, r, "ip saddr { 203.0.113.0/24, 192.0.2.7 } tcp dport 3000")
}

// Example 06: two silos, both 30303, each on its own pool address, in and out.
func TestPoolAddresses(t *testing.T) {
	spec := v1.SiloSpec{Service: &v1.Service{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}, {Name: "disc", Port: 30303, Protocol: "UDP"}},
		Expose: v1.ExposeLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool, Pool: "metal-1-extra"}},
		Network: v1.SiloNetwork{Egress: v1.Egress{Source: v1.EgressSameAsService}}}
	r := Rules(host(
		Silo{Key: "web3/eth-node-a", IP: a("10.64.2.2"), Spec: spec, PublicIP: a("198.51.100.17"), EgressIP: a("198.51.100.17")},
		Silo{Key: "web3/eth-node-b", IP: a("10.64.2.3"), Spec: spec, PublicIP: a("198.51.100.18"), EgressIP: a("198.51.100.18")},
	))
	has(t, r,
		"ip daddr 198.51.100.17 tcp dport 30303 dnat ip to 10.64.2.2:30303",
		"ip daddr 198.51.100.18 tcp dport 30303 dnat ip to 10.64.2.3:30303",
		"ip saddr 10.64.2.2 ip daddr", "snat ip to 198.51.100.17",
		"ip saddr 10.64.2.3 ip daddr", "snat ip to 198.51.100.18",
	)
}

// allowFrom: same host (bridged) and across the mesh (routed); the source must be running.
func TestAllowFrom(t *testing.T) {
	api := Silo{Key: "payments/api", IP: a("10.64.2.2"), Spec: v1.SiloSpec{
		Service:   &v1.Service{Ports: []v1.ServicePort{{Name: "http", Port: 8080}, {Name: "admin", Port: 9090}}},
		AllowFrom: []v1.AllowFrom{{Silo: "worker", Ports: []string{"http"}}, {Silo: "research/crawler"}, {Silo: "ghost"}},
	}}
	worker := Silo{Key: "payments/worker", IP: a("10.64.2.5")}   // same host
	crawler := Silo{Key: "research/crawler", IP: a("10.64.7.9")} // another host
	h := host(api, worker)
	h.All = []Silo{api, worker, crawler, {Key: "payments/ghost"}} // ghost has no address: not running
	r := Rules(h)
	has(t, r,
		"ip saddr 10.64.2.5 ip daddr 10.64.2.2 tcp dport 8080 accept",                 // worker → http, bridged
		`oifname "kvbr0" ip saddr 10.64.7.9 ip daddr 10.64.2.2 tcp dport 8080 accept`, // crawler → all ports, routed
		`oifname "kvbr0" ip saddr 10.64.7.9 ip daddr 10.64.2.2 tcp dport 9090 accept`,
		`iifname "kvt*" oifname "kvt*" drop`,
	)
	hasNot(t, r, "ip saddr 10.64.2.5 ip daddr 10.64.2.2 tcp dport 9090") // worker only got http
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
	hasNot(t, r, "dnat", "snat ip to")
	if Rules(host(Silo{Key: "dev/plain", IP: a("10.64.2.2")})) != r {
		t.Error("not deterministic")
	}
}
