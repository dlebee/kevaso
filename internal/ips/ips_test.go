package ips

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func at(min int) *time.Time { t := t0.Add(time.Duration(min) * time.Minute); return &t }

func ip(name string, mut ...func(*v1.IP)) *v1.IP {
	x := &v1.IP{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "ip-" + name}, Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "us-ord"}}
	for _, m := range mut {
		m(x)
	}
	return x
}

func heldBy(uid string) func(*v1.IP) {
	return func(x *v1.IP) { x.Status.Holder = &v1.IPHolder{Holder: "silo/x", UID: uid} }
}

func hostIP(name, addr string) func(*v1.IP) {
	return func(x *v1.IP) { x.Spec = v1.IPSpec{Type: v1.IPTypeHost, HostAddress: addr} }
}

// silo names ipName on a HostPort service (hostPort.ip) opening port 30303 as as (0: its own).
func silo(name, ipName string, created int, as int) *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "silo-" + name, CreationTimestamp: at(created)},
		Spec: v1.SiloSpec{
			Ports:    []v1.SiloPort{{Name: "p2p", Port: 30303}},
			Services: []v1.SiloService{{Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: ipName}, Ports: []v1.ServicePort{{Port: "p2p", As: as}}}},
		}}
}

func lbService(name, ipName string, created int) *v1.Service {
	return &v1.Service{ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "web3", UID: "svc-" + name, CreationTimestamp: at(created)},
		Spec: v1.ServiceSpec{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode", IP: ipName}, Ports: []v1.ServicePortSpec{{Name: "https", Port: 443}}}}
}

func holders(cs []Claim) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Holder+"="+strings.Join(c.Ports, ","))
	}
	return strings.Join(out, " ")
}

func TestClaims(t *testing.T) {
	egress := silo("out", "", 3, 0)
	egress.Spec.Services = nil
	egress.Spec.Network.Egress.Source = &v1.EgressSource{IP: "eth"}
	lbSilo := silo("bal", "", 4, 0)
	lbSilo.Spec.Services[0] = v1.SiloService{Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "linode", IP: "eth"}, Ports: []v1.ServicePort{{Port: "p2p", As: 443}}}
	other := silo("far", "eth", 0, 0)
	other.Namespace = "elsewhere"
	worker := silo("w", "", 0, 0)
	worker.Spec.Services[0].HostPort = &v1.HostPortSource{Worker: v1.NetworkExternal}
	for _, c := range []struct {
		name  string
		silos []*v1.Silo
		svcs  []*v1.Service
		want  string
	}{
		{"nobody", nil, nil, ""},
		{"oldest first", []*v1.Silo{silo("b", "eth", 2, 0), silo("a", "eth", 1, 8545)}, nil, "silo/a=8545/TCP silo/b=30303/TCP"},
		{"same time: by name", []*v1.Silo{silo("b", "eth", 1, 0), silo("a", "eth", 1, 0)}, nil, "silo/a=30303/TCP silo/b=30303/TCP"},
		{"egress names it, no ports", []*v1.Silo{egress}, nil, "silo/out="},
		{"loadBalancer.ip", []*v1.Silo{lbSilo}, nil, "silo/bal=443/TCP"},
		{"a Service's loadBalancer.ip", nil, []*v1.Service{lbService("pub", "eth", 5), lbService("other", "x", 0)}, "service/pub=443/TCP"},
		{"silos and services together", []*v1.Silo{silo("a", "eth", 9, 0)}, []*v1.Service{lbService("pub", "eth", 5)}, "service/pub=443/TCP silo/a=30303/TCP"},
		{"another namespace's", []*v1.Silo{other}, nil, ""},
		{"another IP or none", []*v1.Silo{silo("a", "x", 0, 0), worker}, nil, ""},
	} {
		if got := holders(Claims(ip("eth"), c.silos, c.svcs)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	placed := silo("a", "eth", 0, 0)
	placed.Status.Host = "hv1"
	now := time.Now()
	placed.DeletionTimestamp = &now
	cs := Claims(ip("eth"), []*v1.Silo{placed}, nil)
	if len(cs) != 1 || cs[0].Host != "hv1" || !cs[0].Deleting || cs[0].UID != "silo-a" {
		t.Errorf("claim fields: %+v", cs)
	}
}

func TestBind(t *testing.T) {
	now := time.Now()
	claim := func(name string, deleting bool) Claim {
		return Claim{Holder: "silo/" + name, UID: "silo-" + name, Deleting: deleting}
	}
	for _, c := range []struct {
		name    string
		ip      *v1.IP
		claims  []Claim
		holder  string   // "" = nobody
		waiting []string // UIDs
		reason  string   // in every waiting reason
	}{
		{"nobody claims it", ip("eth"), nil, "", nil, ""},
		{"the oldest takes it", ip("eth"), []Claim{claim("a", false), claim("b", false)}, "silo-a", []string{"silo-b"}, "one holder at a time"},
		{"the holder keeps it over an older one", ip("eth", heldBy("silo-b")), []Claim{claim("a", false), claim("b", false)}, "silo-b", []string{"silo-a"}, "held by silo/b"},
		{"the holder keeps it while deleting", ip("eth", heldBy("silo-a")), []Claim{claim("a", true), claim("b", false)}, "silo-a", []string{"silo-b"}, "held by silo/a"},
		{"a deleting claim takes nothing new", ip("eth"), []Claim{claim("a", true), claim("b", false)}, "silo-b", nil, ""},
		{"a gone holder lets it go", ip("eth", heldBy("silo-gone")), []Claim{claim("b", false)}, "silo-b", nil, ""},
		{"only deleting claims", ip("eth"), []Claim{claim("a", true)}, "", nil, ""},
		{"the IP is being released", ip("eth", func(x *v1.IP) { x.DeletionTimestamp = &now }), []Claim{claim("a", false)}, "", []string{"silo-a"}, "being released"},
		{"released: its holder keeps it", ip("eth", heldBy("silo-a"), func(x *v1.IP) { x.DeletionTimestamp = &now }), []Claim{claim("a", false), claim("b", false)}, "silo-a", []string{"silo-b"}, "being released"},
	} {
		d := Decide(c.ip, c.claims)
		got := ""
		if d.Holder != nil {
			got = d.Holder.UID
		}
		if got != c.holder {
			t.Errorf("%s: holder %q, want %q", c.name, got, c.holder)
		}
		if sh := d.StatusHolder(); (sh == nil) != (c.holder == "") || (sh != nil && sh.UID != c.holder) {
			t.Errorf("%s: status holder %+v", c.name, sh)
		}
		var uids []string
		for _, w := range d.Waiting {
			uids = append(uids, w.UID)
			if !strings.Contains(w.Reason, c.reason) {
				t.Errorf("%s: reason %q, want %q in it", c.name, w.Reason, c.reason)
			}
		}
		if strings.Join(uids, ",") != strings.Join(c.waiting, ",") {
			t.Errorf("%s: waiting %v, want %v", c.name, uids, c.waiting)
		}
	}
}

func TestCanDelete(t *testing.T) {
	if why := CanDelete(ip("eth")); why != "" {
		t.Errorf("reserved, held by nobody: %q", why)
	}
	held := ip("eth", func(x *v1.IP) { x.Status.Holder = &v1.IPHolder{Holder: "silo/a", UID: "u", Ports: []string{"443/TCP"}} })
	if why := CanDelete(held); !strings.Contains(why, "held by silo/a (443/TCP)") {
		t.Errorf("held: %q", why)
	}
}

func host(name, main string, addrs ...v1.HostAddress) *v1.Host {
	return &v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Spec: v1.HostSpec{ExternalIP: main, Addresses: addrs}}
}

func addr(name, a string) v1.HostAddress {
	return v1.HostAddress{Name: name, Kind: v1.NetworkExternal, Address: a}
}

func TestFindAddress(t *testing.T) {
	hosts := []*v1.Host{host("hv1", "198.51.100.1", addr("mail", "198.51.100.7")), host("hv2", "203.0.113.1", addr("web", "203.0.113.21"))}
	for _, c := range []struct{ name, host, addr string }{
		{"mail", "hv1", "198.51.100.7"},
		{"web", "hv2", "203.0.113.21"},
		{"none", "", ""},
	} {
		h, a, ok := FindAddress(hosts, c.name)
		got := ""
		if ok {
			got = h.Name
		}
		if got != c.host || a.Address != c.addr || ok != (c.host != "") {
			t.Errorf("%s: %s %s %v, want %s %s", c.name, got, a.Address, ok, c.host, c.addr)
		}
	}
}

func TestDuplicates(t *testing.T) {
	for _, c := range []struct {
		name  string
		hosts []*v1.Host
		want  string // "" = fine
	}{
		{"none", nil, ""},
		{"distinct", []*v1.Host{host("a", "1.1.1.1", addr("x", "1.1.1.2")), host("b", "2.2.2.2", addr("y", "2.2.2.3"))}, ""},
		{"same name on two hosts", []*v1.Host{host("a", "", addr("x", "1.1.1.2")), host("b", "", addr("x", "2.2.2.3"))}, "address name x is a's already"},
		{"same address on two hosts", []*v1.Host{host("a", "", addr("x", "1.1.1.2")), host("b", "", addr("y", "1.1.1.2"))}, "address 1.1.1.2 (y on b) is a (x) already"},
		{"another host's main IP", []*v1.Host{host("a", "1.1.1.1"), host("b", "", addr("y", "1.1.1.1"))}, "is a's main IP already"},
		{"its own main IP", []*v1.Host{host("a", "1.1.1.1", addr("y", "1.1.1.1"))}, "is a's main IP already"},
	} {
		got := Duplicates(c.hosts)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckHostAddresses(t *testing.T) {
	reserved := func(name, hostName, addrName, a string) *v1.IP {
		return ip(name, hostIP(name, addrName), func(x *v1.IP) { x.Status.Host = hostName; x.Status.Address = a })
	}
	all := []*v1.IP{reserved("x", "hv2", "web", "203.0.113.21"), reserved("y", "hv1", "mail", "198.51.100.7"), ip("p", func(x *v1.IP) { x.Status.Host = "hv2"; x.Status.Address = "9.9.9.9" })}
	for _, c := range []struct {
		name string
		host string
		next []v1.HostAddress
		want string
	}{
		{"keeping it", "hv2", []v1.HostAddress{addr("web", "203.0.113.21")}, ""},
		{"keeping it, adding one", "hv2", []v1.HostAddress{addr("web", "203.0.113.21"), addr("new", "203.0.113.22")}, ""},
		{"removing it", "hv2", nil, "web 203.0.113.21 (IP web3/x)"},
		{"renaming it", "hv2", []v1.HostAddress{addr("www", "203.0.113.21")}, "web 203.0.113.21 (IP web3/x)"},
		{"changing its address", "hv2", []v1.HostAddress{addr("web", "203.0.113.22")}, "web 203.0.113.21 (IP web3/x)"},
		{"another host's", "hv3", nil, ""},
	} {
		got := CheckHostAddresses(c.host, c.next, all)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	unbound := []*v1.IP{ip("z", hostIP("z", "web"), func(x *v1.IP) { x.Status.Host = "hv2" })}
	if why := CheckHostAddresses("hv2", nil, unbound); why != "" {
		t.Errorf("an IP without its address yet: %q", why)
	}
}

func TestTogether(t *testing.T) {
	hosts := []*v1.Host{host("hv1", "", addr("a1", "1.1.1.2"), addr("a2", "1.1.1.3")), host("hv2", "", addr("b1", "2.2.2.3"))}
	h := func(name, a string) *v1.IP { return ip(name, hostIP(name, a)) }
	for _, c := range []struct {
		name  string
		named []*v1.IP
		want  string
	}{
		{"none", nil, ""},
		{"one", []*v1.IP{h("x", "a1")}, ""},
		{"one host's two", []*v1.IP{h("x", "a1"), h("y", "a2")}, ""},
		{"two hosts'", []*v1.IP{h("x", "a1"), h("y", "b1")}, "IP x is on host hv1 and IP y on host hv2"},
		{"a provider IP goes anywhere", []*v1.IP{h("x", "a1"), ip("p")}, ""},
		{"an address no host has yet", []*v1.IP{h("x", "a1"), h("y", "later")}, ""},
		{"a missing IP", []*v1.IP{nil, h("y", "b1")}, ""},
	} {
		got := Together(c.named, hosts)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.21", ""},
		{"203.0.113.0/30", "is a range"},
		{"203.0.113.21/32", "is a range"},
		{"2001:db8::1", "IPv6 comes later"},
		{"web", "isn't an address"},
		{"", "isn't an address"},
	} {
		a, err := ParseAddress(c.in)
		switch {
		case c.want == "" && (err != nil || a.String() != c.in):
			t.Errorf("%q: %v %v", c.in, a, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%q: %v, want %q", c.in, err, c.want)
		}
	}
}
