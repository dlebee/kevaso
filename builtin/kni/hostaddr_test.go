package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A host port answers on the host's internal and/or external IP only, as its service port asks
// (design §7.0): never on Kevaso's mesh or silo ranges, and only for traffic to those addresses,
// so a local silo's own connection to the same port elsewhere isn't caught.
func TestHostPortOnTheHostsIPs(t *testing.T) {
	spec := func(hostPort ...string) v1.SiloSpec {
		return v1.SiloSpec{Ports: []v1.SiloPort{{Name: "p2p", Port: 30303}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "p2p", HostPort: hostPort}}}}
	}
	node := Silo{Key: "web3/node", IP: a("10.64.2.2"), Spec: spec(v1.NetworkInternal, v1.NetworkExternal)}
	client := Silo{Key: "web3/client", IP: a("10.64.2.3"), Spec: v1.SiloSpec{}}
	r := Rules(host(node, client))
	var dnat []string
	for _, l := range strings.Split(r, "\n") {
		if strings.Contains(l, "dport 30303") && strings.Contains(l, "dnat ip to") {
			dnat = append(dnat, strings.TrimSpace(l))
		}
	}
	want := "ip daddr { 10.0.0.5, 198.51.100.10 } tcp dport 30303 dnat ip to 10.64.2.2:30303"
	if len(dnat) != 1 || dnat[0] != want {
		t.Fatalf("the host port's DNAT:\n%s\nwant\n%s", strings.Join(dnat, "\n"), want)
	}
	// Every rule taking port 30303 matches on its destination being the host's own: a connection
	// from the client silo to 30303 on some other machine goes out untouched.
	for _, l := range strings.Split(r, "\n") {
		if strings.Contains(l, "dport 30303") && (strings.Contains(l, "dnat") && !strings.Contains(l, "ct status dnat") || strings.Contains(l, "redirect")) &&
			!strings.Contains(l, "ip daddr { 10.0.0.5, 198.51.100.10 }") {
			t.Errorf("a rule on 30303 without the host's own destination: %s", l)
		}
	}
	// One network: only that address. (worker-ip is gone: hostPort external is its equivalent.)
	ext := Rules(host(Silo{Key: "web3/e", IP: a("10.64.2.4"), Spec: spec(v1.NetworkExternal)}))
	has(t, ext, "ip daddr 198.51.100.10 tcp dport 30303 dnat ip to 10.64.2.4:30303")
	hasNot(t, ext, "10.0.0.5 tcp dport 30303")
	in := Rules(host(Silo{Key: "web3/i", IP: a("10.64.2.6"), Spec: spec(v1.NetworkInternal)}))
	has(t, in, "ip daddr 10.0.0.5 tcp dport 30303 dnat ip to 10.64.2.6:30303")
	hasNot(t, in, "198.51.100.10 tcp dport 30303")
	// ip-pool: on its own load-balancer address only.
	pool := v1.SiloSpec{Ports: []v1.SiloPort{{Name: "p2p", Port: 30303}}, Service: &v1.SiloService{
		Ports: []v1.ServicePort{{Port: "p2p", LoadBalancer: true}}, LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool}}}
	pr := Rules(host(Silo{Key: "web3/p", IP: a("10.64.2.5"), Spec: pool, LoadBalancerIP: a("192.168.1.50")}))
	has(t, pr, "ip daddr 192.168.1.50 tcp dport 30303 dnat ip to 10.64.2.5:30303")
	hasNot(t, pr, "ip daddr { 10.0.0.5")
}
