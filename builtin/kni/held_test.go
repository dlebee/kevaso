package kni

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Design §0.6: a silo its routeWhen holds has no outside rule on its exposed ports and node
// ports, and nothing is cut (established connections stay); private access stays. A port is open
// only when its lease and its routing both say so.
func TestHeldPorts(t *testing.T) {
	ext := []string{v1.NetworkExternal}
	spec := v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "rpc", Port: 8545}, {Name: "debug", Port: 9229}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{
			{Port: "rpc", HostPort: ext, AllowFrom: []string{"client"}},
			{Port: "debug", HostPort: ext, Lease: &v1.PortLease{}, AllowFrom: []string{"client"}},
		}},
	}
	client := Silo{Key: "dev/client", IP: a("10.64.2.9")}
	base := Silo{Key: "dev/rpc", IP: a("10.64.2.2"), Spec: spec, Leased: []string{"debug"}}
	const (
		rpcDNAT   = "ip daddr 198.51.100.10 tcp dport 8545 dnat ip to 10.64.2.2:8545"
		debugDNAT = "ip daddr 198.51.100.10 tcp dport 9229 dnat ip to 10.64.2.2:9229"
		debugCut  = `oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 9229 ct status dnat ct original ip daddr 198.51.100.10 reject with tcp reset`
		private   = "ip saddr 10.64.2.9 ip daddr 10.64.2.2 tcp dport 8545 accept"
		anyCut    = "ct status dnat ct original"
	)
	for _, c := range []struct {
		name         string
		held         bool
		closed       []string
		want, absent []string
	}{
		{"routed, lease open: both open", false, nil, []string{rpcDNAT, debugDNAT, private}, []string{anyCut}},
		{"routed, lease closed: the lease closes it and cuts", false, []string{"debug"}, []string{rpcDNAT, debugCut, private}, []string{debugDNAT}},
		{"held, lease open: no rule, nothing cut", true, nil, []string{private}, []string{rpcDNAT, debugDNAT, anyCut}},
		{"held, lease closed: no rule, the lease's cut stays", true, []string{"debug"}, []string{debugCut, private}, []string{rpcDNAT, debugDNAT}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := base
			s.Held, s.Closed = c.held, c.closed
			for _, p := range []string{"rpc", "debug"} {
				open, cut := Outside(s, p)
				wantOpen := !c.held && !contains(c.closed, p)
				if open != wantOpen || cut != contains(c.closed, p) {
					t.Errorf("Outside(%s): open %v cut %v", p, open, cut)
				}
			}
			h := host(s)
			h.All = []Silo{client}
			r := Rules(h)
			has(t, r, c.want...)
			hasNot(t, r, c.absent...)
		})
	}
}

func TestHeldNodePorts(t *testing.T) {
	s := Silo{Key: "dev/rpc", IP: a("10.64.2.2"), Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "rpc", Port: 8545}}, Service: &v1.SiloService{
		Ports:        []v1.ServicePort{{Port: "rpc", LoadBalancer: true}},
		LoadBalancer: &v1.LoadBalancerSpec{Class: "linode-nodebalancer"},
	}}, NodePorts: []v1.NodePort{{Name: "rpc", Port: 8545, NodePort: 30001}}, SourceRanges: []string{"192.168.255.0/24"}}
	const nodeDNAT = "ip saddr 192.168.255.0/24 tcp dport 30001 dnat ip to 10.64.2.2:8545"
	has(t, Rules(host(s)), nodeDNAT)
	s.Held = true
	r := Rules(host(s))
	hasNot(t, r, nodeDNAT, "ct status dnat ct original")
}
