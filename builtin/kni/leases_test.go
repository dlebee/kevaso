package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Design §7.2d: a leased port has no outside rule while no lease is active; open, it takes the
// port's own sources; its connections are cut once it closes; private access never changes.
func TestLeasedPorts(t *testing.T) {
	ext := []string{v1.NetworkExternal}
	spec := func() v1.SiloSpec {
		return v1.SiloSpec{
			Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "disc", Port: 30303, Protocol: "UDP"}},
			Service: &v1.SiloService{Ports: []v1.ServicePort{
				{Port: "web", HostPort: ext, Sources: []string{"203.0.113.0/24"}},
				{Port: "debug", HostPort: ext, Sources: []string{"203.0.113.7"}, Lease: &v1.PortLease{}, AllowFrom: []string{"worker"}},
				{Port: "disc", HostPort: ext, Sources: []string{"203.0.113.64/26"}, Lease: &v1.PortLease{}},
			}},
		}
	}
	worker := Silo{Key: "dev/worker", IP: a("10.64.2.9")}
	base := func() Silo {
		return Silo{Key: "dev/api", IP: a("10.64.2.2"), Spec: spec(), Leased: []string{"debug", "disc"}}
	}
	const (
		webDNAT    = "ip daddr 198.51.100.10 tcp dport 8080 dnat ip to 10.64.2.2:8080"
		webFwd     = `oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.0/24 tcp dport 8080 ct original ip daddr 198.51.100.10 ct status dnat accept`
		debugDNAT  = "ip daddr 198.51.100.10 tcp dport 9229 dnat ip to 10.64.2.2:9229"
		debugFwd   = `oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.7 tcp dport 9229 ct original ip daddr 198.51.100.10 ct status dnat accept`
		discDNAT   = "ip daddr 198.51.100.10 udp dport 30303 dnat ip to 10.64.2.2:30303"
		discFwd    = `oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.64/26 udp dport 30303 ct original ip daddr 198.51.100.10 ct status dnat accept`
		debugCut   = `oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 9229 ct status dnat ct original ip daddr 198.51.100.10 reject with tcp reset`
		debugCutRx = `iifname "kvbr0" ip saddr 10.64.2.2 tcp sport 9229 ct status dnat ct original ip daddr 198.51.100.10 reject with tcp reset`
		discCut    = `oifname "kvbr0" ip daddr 10.64.2.2 udp dport 30303 ct status dnat ct original ip daddr 198.51.100.10 drop`
		private    = "ip saddr 10.64.2.9 ip daddr 10.64.2.2 tcp dport 9229 accept"
	)
	// (The old cases narrowing a lease's sources below the service's (lease.allowFrom) are gone:
	// a leased port's sources are the port's own, covered here per port.)
	for _, c := range []struct {
		name      string
		mod       func(*Silo)
		want, not []string
	}{
		{"closed: no rule, cut", func(s *Silo) { s.Closed = []string{"debug", "disc"} },
			[]string{webDNAT, webFwd, debugCut, debugCutRx, discCut, private}, []string{debugDNAT, debugFwd, discDNAT, discFwd}},
		{"open: each with its own port's sources", func(s *Silo) {},
			[]string{webDNAT, webFwd, debugDNAT, debugFwd, discDNAT, discFwd, private},
			[]string{debugCut, discCut, "ip saddr 203.0.113.0/24 tcp dport 9229", "ip saddr 203.0.113.0/24 udp"}},
		{"one open, one closed, on their own", func(s *Silo) { s.Closed = []string{"disc"} },
			[]string{debugDNAT, debugFwd, discCut, private}, []string{debugCut, discDNAT, discFwd}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := base()
			c.mod(&s)
			h := host(s)
			h.All = []Silo{worker}
			r := Rules(h)
			has(t, r, c.want...)
			hasNot(t, r, c.not...)
			// Cuts come before the rule that lets established traffic through.
			if i, j := strings.Index(r, "ct status dnat ct original"), strings.Index(r, `oifname "kvbr0" ct state established,related accept`); i >= 0 && i > j {
				t.Error("cut rules after the established accept")
			}
		})
	}
}

func TestLeasedNodePorts(t *testing.T) {
	s := Silo{Key: "dev/api", IP: a("10.64.2.2"), Spec: v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}},
		Service: &v1.SiloService{
			Ports:        []v1.ServicePort{{Port: "web", LoadBalancer: true}, {Port: "debug", LoadBalancer: true, Lease: &v1.PortLease{}}},
			LoadBalancer: &v1.LoadBalancerSpec{Class: "linode-nodebalancer"},
		}}, NodePorts: []v1.NodePort{{Name: "web", Port: 8080, NodePort: 30001}, {Name: "debug", Port: 9229, NodePort: 30002}},
		SourceRanges: []string{"192.168.255.0/24"}, Leased: []string{"debug"}, Closed: []string{"debug"}}
	r := Rules(host(s))
	has(t, r,
		"ip saddr 192.168.255.0/24 tcp dport 30001 dnat ip to 10.64.2.2:8080",
		`oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 9229 ct status dnat ct original proto-dst 30002 reject with tcp reset`)
	hasNot(t, r, "dport 30002 dnat")
	s.Closed = nil
	r = Rules(host(s))
	has(t, r, "ip saddr 192.168.255.0/24 tcp dport 30002 dnat ip to 10.64.2.2:9229")
	hasNot(t, r, "ct original")
}
