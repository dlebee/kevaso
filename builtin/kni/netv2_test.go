package kni

import (
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Networking v2 on a worker: several services on one silo, each its own way in and its own rules.

const mailIP = "203.0.113.21" // an IP (type Host) on this host's uplink, held by the shop silo

// shop declares web 8080, api 8443, metrics 9090 and opens each in its own service: web on the
// worker's external IP as 80, api on the IP "edge" as 443, metrics Internal to prometheus.
func shop() Silo {
	return Silo{Key: "dev/shop", IP: a("10.64.2.2"), Tap: "kvt02", MAC: "02:00:00:00:00:02", Spec: v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "api", Port: 8443}, {Name: "metrics", Port: 9090}},
		Services: []v1.SiloService{
			{Name: "web", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "web", As: 80}}},
			{Name: "api", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge"},
				Ports: []v1.ServicePort{{Port: "api", As: 443, AllowFrom: []string{"probe"}}}},
			{Name: "metrics", Ports: []v1.ServicePort{{Port: "metrics", AllowFrom: []string{"prometheus"}}}},
		}},
		Addrs: map[string]netip.Addr{"api": a(mailIP)},
	}
}

func outside(dst string, port int) pkt {
	return pkt{iif: "eth0", saddr: a("192.0.2.50"), daddr: a(dst), proto: "tcp", dport: port}
}

func TestHostPortOnAnIPOpensOnThatAddress(t *testing.T) {
	s := shop()
	h := host(s)
	rs := parseNFT(t, Rules(h))
	for _, c := range []struct {
		dst  string
		port int
		want string // ADDR:PORT reached, "" for nothing
	}{
		{mailIP, 443, "10.64.2.2:8443"},         // api on its IP
		{"198.51.100.10", 80, "10.64.2.2:8080"}, // web on the worker's external IP
		{"198.51.100.10", 443, ""},              // api isn't on the worker's address
		{mailIP, 80, ""},                        // web isn't on the IP
		{"10.0.0.5", 443, ""},                   // nor on the internal one
		{"10.64.2.2", 9090, ""},                 // metrics is Internal: not from outside
		{"203.0.113.99", 443, ""},               // another address altogether
	} {
		got, ok := rs.reaches(t, h, outside(c.dst, c.port))
		if c.want == "" && ok || c.want != "" && (!ok || got.String() != c.want) {
			t.Errorf("%s:%d reaches %v %v, want %q", c.dst, c.port, got, ok, c.want)
		}
	}
	// allowFrom works on a HostPort service too, on the silo IP.
	probe := Silo{Key: "dev/probe", IP: a("10.64.3.4")}
	h.All = []Silo{probe}
	has(t, Rules(h), `oifname "kvbr0" ip saddr 10.64.3.4 ip daddr 10.64.2.2 tcp dport 8443 accept`)
}

func TestHostPortOnAnIPNotHereOpensNothing(t *testing.T) {
	s := shop()
	s.Addrs = nil // the IP is on another host, or not held yet
	r, problems := Generate(host(s))
	hasNot(t, r, "dport 443 dnat")
	has(t, r, "ip daddr 198.51.100.10 tcp dport 80 dnat ip to 10.64.2.2:8080") // the other service is unaffected
	if !problemHas(problems, "that IP isn't held by this silo on this host") {
		t.Fatalf("no problem said: %v", problems)
	}
	// own works the same way: the instance's own member, by service.
	own := shop()
	own.Spec.Services[1].HostPort = &v1.HostPortSource{Own: true}
	has(t, Rules(host(own)), "ip daddr "+mailIP+" tcp dport 443 dnat ip to 10.64.2.2:8443")
}

func TestTwoSilosOnOneIPPortOpenNeither(t *testing.T) {
	x, y := shop(), shop()
	y.Key, y.IP, y.Tap, y.MAC = "dev/shop2", a("10.64.2.3"), "kvt03", "02:00:00:00:00:03"
	r, problems := Generate(host(x, y))
	hasNot(t, r, "ip daddr "+mailIP+" tcp dport 443 dnat")
	if !problemHas(problems, "it is not settled which one holds it") {
		t.Fatalf("problems %v", problems)
	}
}

// Readiness per service: a held service's outside rule goes, the others' stay.
func TestHeldServiceOnlyClosesItsOwnPorts(t *testing.T) {
	s := shop()
	s.HeldServices = []string{"api"}
	r := Rules(host(s))
	hasNot(t, r, "dport 443 dnat")
	has(t, r, "ip daddr 198.51.100.10 tcp dport 80 dnat ip to 10.64.2.2:8080")
	// A port in two services, one held: open through the other.
	two := shop()
	two.Spec.Services = append(two.Spec.Services, v1.SiloService{Name: "api-worker", Type: v1.ServiceHostPort, Ports: []v1.ServicePort{{Port: "api", As: 443}}})
	two.HeldServices = []string{"api"}
	r = Rules(host(two))
	has(t, r, "ip daddr 198.51.100.10 tcp dport 443 dnat ip to 10.64.2.2:8443")
	hasNot(t, r, "ip daddr "+mailIP+" tcp dport 443")
	if strings.Count(r, `oifname "kvbr0" ip saddr 10.64.3.4`) > 1 {
		t.Fatal("a repeated rule")
	}
}

// Leases per port on a HostPort on an IP: a closed lease cuts what it let in on that address.
func TestLeaseOnAnIPCuts(t *testing.T) {
	s := shop()
	s.Spec.Services[1].Ports[0].Lease = &v1.PortLease{}
	s.Leased, s.Closed = []string{"api"}, []string{"api"}
	r := Rules(host(s))
	hasNot(t, r, "dport 443 dnat")
	has(t, r, `oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 8443 ct status dnat ct original ip daddr `+mailIP+` reject with tcp reset`)
}

// Egress: out from the IP when the worker says so (SNAT), else the worker's address; a silo
// with a wide grant still can't reach the host on its extra address.
func TestEgressFromAnIP(t *testing.T) {
	e, err := v1.EgressRule{To: "0.0.0.0/0", Ports: []string{"22", "443"}}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	s := shop()
	s.Egress = []v1.ParsedEgress{e}
	s.EgressIP = a(mailIP)
	h := host(s)
	h.OwnIPs = []netip.Addr{a(mailIP)}
	r := Rules(h)
	has(t, r, `ip saddr 10.64.2.2 ip daddr != { 10.64.0.0/16, 10.62.0.0/16, 10.63.0.0/16 } oifname != "kvbr0" snat ip to `+mailIP)
	rs := parseNFT(t, r)
	if out, _ := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP, daddr: a("192.0.2.80"), proto: "tcp", dport: 443}); !out {
		t.Fatal("a granted address isn't reached")
	}
	if out, _ := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP, daddr: a(mailIP), proto: "tcp", dport: 22}); out {
		t.Fatal("the host's extra address is reached from a silo") // (443 there is the hostPort: hairpinned, like the worker's)
	}
	// No egress IP: no SNAT (masquerade: the worker's address); and nothing out without a grant.
	s.EgressIP, s.Egress = netip.Addr{}, nil
	h = host(s)
	r = Rules(h)
	hasNot(t, r, "snat ip to")
	if out, _ := parseNFT(t, r).outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP, daddr: a("192.0.2.80"), proto: "tcp", dport: 443}); out {
		t.Fatal("out without a grant")
	}
}

// LoadBalancer backends: the node port is open to the balancer's addresses only, and held only
// when every balancer service in front of the port is held.
func TestNodePortOpenToTheBalancerOnly(t *testing.T) {
	s := Silo{Key: "dev/shop", IP: a("10.64.2.2"), Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "https", Port: 8443}},
		Services: []v1.SiloService{
			{Name: "shop", Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
			{Name: "shop-b", Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
		}},
		NodePorts: []v1.NodePort{{Name: "https", Port: 8443, NodePort: 30001}}, SourceRanges: []string{"192.168.255.0/24"}}
	h := host(s)
	rs := parseNFT(t, Rules(h))
	from := func(src string) pkt {
		return pkt{iif: "eth0", saddr: a(src), daddr: a("198.51.100.10"), proto: "tcp", dport: 30001}
	}
	if got, ok := rs.reaches(t, h, from("192.168.255.7")); !ok || got.String() != "10.64.2.2:8443" {
		t.Fatalf("from the balancer: %v %v", got, ok)
	}
	if _, ok := rs.reaches(t, h, from("192.0.2.50")); ok {
		t.Fatal("the node port is open to anyone")
	}
	s.HeldServices = []string{"shop"}
	has(t, Rules(host(s)), "tcp dport 30001 dnat ip to 10.64.2.2:8443")
	s.HeldServices = []string{"shop", "shop-b"}
	hasNot(t, Rules(host(s)), "tcp dport 30001 dnat")
	s.HeldServices, s.SourceRanges = nil, nil
	hasNot(t, Rules(host(s)), "tcp dport 30001 dnat") // no balancer addresses: closed, not open to all
}
