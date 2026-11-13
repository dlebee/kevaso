package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// A host port answers on the host's internal and external IPs only (design §7.0): never on
// Kevaso's mesh or silo ranges, and only for traffic to those addresses, so a local silo's own
// connection to the same port elsewhere isn't caught.
func TestHostPortOnTheHostsIPs(t *testing.T) {
	spec := v1.SiloSpec{Service: &v1.SiloService{Ports: []v1.ServicePort{{Name: "p2p", Port: 30303}}, Expose: v1.ExposeHostPort}}
	node := Silo{Key: "web3/node", IP: a("10.64.2.2"), Spec: spec, PublicIP: a("198.51.100.10")}
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
	// worker-ip opens on the host's addresses the same way; ip-pool on its own address only.
	wip := spec
	wip.Service = &v1.SiloService{Ports: spec.Service.Ports, Expose: v1.ExposeLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBWorkerIP}}
	has(t, Rules(host(Silo{Key: "web3/w", IP: a("10.64.2.4"), Spec: wip, PublicIP: a("198.51.100.10")})), strings.Replace(want, "10.64.2.2:", "10.64.2.4:", 1))
	pool := spec
	pool.Service = &v1.SiloService{Ports: spec.Service.Ports, Expose: v1.ExposeLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Class: v1.LBIPPool}}
	has(t, Rules(host(Silo{Key: "web3/p", IP: a("10.64.2.5"), Spec: pool, PublicIP: a("192.168.1.50")})), "ip daddr 192.168.1.50 tcp dport 30303 dnat ip to 10.64.2.5:30303")
}
