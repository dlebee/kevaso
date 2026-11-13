package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Design §7.2d: a leased port has no outside rule while no lease is active; open, it takes the
// lease's narrowed sources; its connections are cut once it closes; private access never changes.
func TestLeasedPorts(t *testing.T) {
	spec := func() v1.SiloSpec {
		return v1.SiloSpec{
			Service: &v1.SiloService{
				Ports: []v1.ServicePort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229, Lease: &v1.PortLease{}},
					{Name: "disc", Port: 30303, Protocol: "UDP", Lease: &v1.PortLease{}}},
				Expose:   v1.ExposeHostPort,
				HostPort: &v1.HostPortSpec{AllowFrom: []string{"203.0.113.0/24"}},
			},
			AllowFrom: []v1.AllowFrom{{Silo: "worker", Ports: []string{"debug"}}},
		}
	}
	worker := Silo{Key: "dev/worker", IP: a("10.64.2.9")}
	base := func() Silo {
		return Silo{Key: "dev/api", IP: a("10.64.2.2"), Spec: spec(), PublicIP: a("198.51.100.10"), Leased: []string{"debug", "disc"}}
	}
	const (
		webDNAT    = "fib daddr type local ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16, 127.0.0.0/8 } tcp dport 8080 dnat ip to 10.64.2.2:8080"
		webFwd     = `oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.0/24 tcp dport 8080 ct status dnat accept`
		debugDNAT  = "fib daddr type local ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16, 127.0.0.0/8 } tcp dport 9229 dnat ip to 10.64.2.2:9229"
		discDNAT   = "fib daddr type local ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16, 127.0.0.0/8 } udp dport 30303 dnat ip to 10.64.2.2:30303"
		debugCut   = `oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 9229 ct status dnat ct original ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16 } reject with tcp reset`
		debugCutRx = `iifname "kvbr0" ip saddr 10.64.2.2 tcp sport 9229 ct status dnat ct original ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16 } reject with tcp reset`
		discCut    = `oifname "kvbr0" ip daddr 10.64.2.2 udp dport 30303 ct status dnat ct original ip daddr != { 10.62.0.0/16, 10.63.0.0/16, 10.64.0.0/16, 10.65.0.0/16 } drop`
		private    = "ip saddr 10.64.2.9 ip daddr 10.64.2.2 tcp dport 9229 accept"
	)
	for _, c := range []struct {
		name      string
		mod       func(*Silo)
		want, not []string
	}{
		{"closed: no rule, cut", func(s *Silo) { s.Closed = []string{"debug", "disc"} },
			[]string{webDNAT, webFwd, debugCut, debugCutRx, discCut, private}, []string{debugDNAT, discDNAT, "ip saddr 203.0.113.0/24 tcp dport 9229"}},
		{"open: the service's sources", func(s *Silo) { s.Closed = []string{"disc"} },
			[]string{webDNAT, debugDNAT, `oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.0/24 tcp dport 9229 ct status dnat accept`, discCut, private},
			[]string{debugCut, discDNAT}},
		{"open: each narrowed by its own lease", func(s *Silo) {
			s.LeaseFrom = map[string][]string{"debug": {"203.0.113.7"}, "disc": {"203.0.113.64/26"}}
		},
			[]string{webFwd, debugDNAT, discDNAT,
				`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.7 tcp dport 9229 ct status dnat accept`,
				`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.64/26 udp dport 30303 ct status dnat accept`},
			[]string{debugCut, discCut, "ip saddr 203.0.113.0/24 tcp dport 9229", "ip saddr 203.0.113.7 udp"}},
		{"open: one narrowed, one with the service's sources", func(s *Silo) { s.LeaseFrom = map[string][]string{"debug": {"203.0.113.7"}} },
			[]string{`ip saddr 203.0.113.7 tcp dport 9229 ct status dnat accept`,
				`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 203.0.113.0/24 udp dport 30303 ct status dnat accept`},
			[]string{debugCut, discCut}},
		{"one open, one closed, on their own", func(s *Silo) {
			s.Closed = []string{"disc"}
			s.LeaseFrom = map[string][]string{"debug": {"203.0.113.7"}}
		},
			[]string{`ip saddr 203.0.113.7 tcp dport 9229 ct status dnat accept`, discCut}, []string{debugCut, discDNAT}},
		{"open, but no source may use it", func(s *Silo) { s.LeaseFrom = map[string][]string{"debug": {}} },
			[]string{webDNAT, debugCut, discDNAT}, []string{debugDNAT, discCut}},
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
			if i, j := strings.Index(r, "ct original"), strings.Index(r, `oifname "kvbr0" ct state established,related accept`); i >= 0 && i > j {
				t.Error("cut rules after the established accept")
			}
		})
	}
}

func TestLeasedNodePorts(t *testing.T) {
	s := Silo{Key: "dev/api", IP: a("10.64.2.2"), Spec: v1.SiloSpec{Service: &v1.SiloService{
		Ports:        []v1.ServicePort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229, Lease: &v1.PortLease{}}},
		Expose:       v1.ExposeLoadBalancer,
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
