package kni

import (
	"net/netip"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Each IPv6 twin on its own (the IPv6 effort): the rule it writes, and what the evaluator says it
// lets through.

const (
	web6 = "fd00:aa:bb:2::2" // the silo's IPv6 address in host6's silo subnet
	ext6 = "2001:db8:e::10"  // the host's external IPv6 address
	int6 = "2001:db8:a::5"   // its internal one
)

// host6 is host() with IPv6: an IPv6 silo subnet (a /64 of a ULA /48), its gateway, and an
// address on each network.
func host6(local ...Silo) Host {
	h := host(local...)
	h.Subnet6, h.Gateway6 = netip.MustParsePrefix("fd00:aa:bb:2::/64"), a("fd00:aa:bb:2::1")
	h.InternalIPv6, h.ExternalIPv6 = a(int6), a(ext6)
	return h
}

func web(spec v1.SiloSpec) Silo {
	return Silo{Key: "dev/web", IP: a("10.64.2.2"), IP6: a(web6), Tap: "kvt02", MAC: "52:4b:00:00:00:02", Spec: spec}
}

func noProblems(t *testing.T, h Host) string {
	t.Helper()
	text, problems := Generate(h)
	if len(problems) > 0 {
		t.Fatalf("problems: %v", problems)
	}
	return text
}

// HostPort on the worker: DNAT from each of the host's IPv6 addresses the port asks for, to the
// silo's IPv6 address (the client's address kept), and the forward accept for what was DNAT.
func TestIPv6HostPortOnTheWorker(t *testing.T) {
	h := host6(web(opens(8443, v1.ServicePort{As: 443}, v1.NetworkExternal)))
	text := noProblems(t, h)
	has(t, text,
		"ip daddr 198.51.100.10 tcp dport 443 dnat ip to 10.64.2.2:8443",
		"ip6 daddr 2001:db8:e::10 tcp dport 443 dnat ip6 to [fd00:aa:bb:2::2]:8443",
		`oifname "kvbr0" ip6 daddr fd00:aa:bb:2::2 tcp dport 8443 ct original ip6 daddr 2001:db8:e::10 ct status dnat accept`)
	hasNot(t, text, "2001:db8:a::5 tcp dport")
	rs := parseNFT(t, text)
	client := a("2001:db8:c::7")
	if got, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: client, daddr: a(ext6), proto: "tcp", dport: 443}); !ok || got.String() != "[fd00:aa:bb:2::2]:8443" {
		t.Fatalf("IPv6 to the external address: %v %v", got, ok)
	}
	for _, p := range []pkt{
		{iif: "eth0", saddr: client, daddr: a(int6), proto: "tcp", dport: 443},  // not on internal
		{iif: "eth0", saddr: client, daddr: a(ext6), proto: "udp", dport: 443},  // not UDP
		{iif: "eth0", saddr: client, daddr: a(ext6), proto: "tcp", dport: 8443}, // not its own number
		{iif: "eth0", saddr: client, daddr: a(web6), proto: "tcp", dport: 8443}, // not the silo directly
	} {
		if got, ok := rs.reaches(t, h, p); ok {
			t.Errorf("%+v reached %v", p, got)
		}
	}

	both := noProblems(t, host6(web(opens(9229, v1.ServicePort{}, v1.NetworkInternal, v1.NetworkExternal))))
	has(t, both, "ip6 daddr 2001:db8:a::5 tcp dport 9229 dnat ip6 to [fd00:aa:bb:2::2]:9229",
		"ip6 daddr 2001:db8:e::10 tcp dport 9229 dnat ip6 to [fd00:aa:bb:2::2]:9229")

	// A host without IPv6 on a network, or a silo without an IPv6 address: IPv4 only, and no
	// problem (the worker gives IPv6 where it has it).
	noExt := host6(web(opens(443, v1.ServicePort{}, v1.NetworkExternal)))
	noExt.ExternalIPv6 = netip.Addr{}
	hasNot(t, noProblems(t, noExt), "dnat ip6")
	s := web(opens(443, v1.ServicePort{}, v1.NetworkExternal))
	s.IP6 = netip.Addr{}
	text = noProblems(t, host6(s))
	hasNot(t, text, "dnat ip6", "ip6 saddr fd00:aa:bb:2::2")
	has(t, text, "dnat ip to 10.64.2.2:443")
}

// Sources by family: an IPv4 list lets no IPv6 client in (closed, not open to all), an IPv6 entry
// opens the IPv6 rule only.
func TestIPv6HostPortSources(t *testing.T) {
	v4only := noProblems(t, host6(web(opens(3000, v1.ServicePort{Sources: []string{"192.0.2.0/24"}}, v1.NetworkExternal))))
	has(t, v4only, "ip saddr 192.0.2.0/24 tcp dport 3000")
	hasNot(t, v4only, "dnat ip6", "ip6 daddr fd00:aa:bb:2::2")

	h := host6(web(opens(3000, v1.ServicePort{Sources: []string{"192.0.2.0/24", "2001:db8:c::/48", "2001:db8:d::9"}}, v1.NetworkExternal)))
	text := noProblems(t, h)
	has(t, text,
		`oifname "kvbr0" ip daddr 10.64.2.2 ip saddr 192.0.2.0/24 tcp dport 3000`,
		`oifname "kvbr0" ip6 daddr fd00:aa:bb:2::2 ip6 saddr { 2001:db8:c::/48, 2001:db8:d::9 } tcp dport 3000 ct original ip6 daddr 2001:db8:e::10 ct status dnat accept`)
	rs := parseNFT(t, text)
	for client, want := range map[string]bool{"2001:db8:c:1::7": true, "2001:db8:d::9": true, "2001:db8:d::8": false, "2001:db8:ffff::c000:207": false} {
		if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: a(client), daddr: a(ext6), proto: "tcp", dport: 3000}); ok != want {
			t.Errorf("from %s: %v, want %v", client, ok, want)
		}
	}
	v6only := noProblems(t, host6(web(opens(3000, v1.ServicePort{Sources: []string{"2001:db8:c::/48"}}, v1.NetworkExternal))))
	hasNot(t, v6only, "dnat ip to")
	has(t, v6only, "dnat ip6 to [fd00:aa:bb:2::2]:3000")
}

// A kept IPv6 IP (hostPort ip, own): one IP, one family, so its service opens over IPv6 only, on
// that address, while the silo holds it here and has an IPv6 address.
func TestIPv6KeptAddress(t *testing.T) {
	spec := v1.SiloSpec{Ports: []v1.SiloPort{{Name: "https", Port: 8443}}, Services: []v1.SiloService{
		{Name: "api", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
		{Name: "api6", Type: v1.ServiceHostPort, HostPort: &v1.HostPortSource{IP: "edge6"}, Ports: []v1.ServicePort{{Port: "https", As: 443}}},
	}}
	s := web(spec)
	s.Addrs = map[string]netip.Addr{"api": a("198.51.100.30"), "api6": a("2001:db8:e::30")}
	h := host6(s)
	text := noProblems(t, h)
	has(t, text,
		"ip daddr 198.51.100.30 tcp dport 443 dnat ip to 10.64.2.2:8443",
		"ip6 daddr 2001:db8:e::30 tcp dport 443 dnat ip6 to [fd00:aa:bb:2::2]:8443",
		`oifname "kvbr0" ip6 daddr fd00:aa:bb:2::2 tcp dport 8443 ct original ip6 daddr 2001:db8:e::30 ct status dnat accept`)
	hasNot(t, text, "2001:db8:e::10 tcp dport 443")
	rs := parseNFT(t, text)
	if got, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: a("2001:db8:c::7"), daddr: a("2001:db8:e::30"), proto: "tcp", dport: 443}); !ok || got.Addr() != a(web6) {
		t.Fatalf("the kept IPv6 address: %v %v", got, ok)
	}
	// Two silos asking for the same kept IPv6 address and port: neither has it.
	o := Silo{Key: "dev/other", IP: a("10.64.2.3"), IP6: a("fd00:aa:bb:2::3"), Tap: "kvt03", Spec: spec, Addrs: s.Addrs}
	two, problems := Generate(host6(s, o))
	hasNot(t, two, "dnat ip6")
	if len(problems) == 0 {
		t.Error("the clash is not reported")
	}
	// Not held here, or no IPv6 address for the silo: not opened, and said.
	s.IP6 = netip.Addr{}
	text, problems = Generate(host6(s))
	hasNot(t, text, "2001:db8:e::30")
	if !hasProblem(problems, "dev/web", "that IP is IPv6 and this silo has no IPv6 address on this host") {
		t.Errorf("not reported: %v", problems)
	}
}

func hasProblem(ps []Problem, owner, reason string) bool {
	for _, p := range ps {
		if p.Owner == owner && strings.Contains(p.Reason, reason) {
			return true
		}
	}
	return false
}

// Outgoing IPv6: what its grants open (IPv6 ranges), from its IPv6 address only, after the
// closed ranges and the host's own addresses; NAT66 masquerade to the host's address, or SNAT to
// its kept IPv6 IP's.
func TestIPv6Egress(t *testing.T) {
	s := web(v1.SiloSpec{})
	s.Egress = []v1.ParsedEgress{
		{Prefix: netip.MustParsePrefix("::/0"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}},
		{Prefix: netip.MustParsePrefix("2001:db8:9::/48"), Protocols: []string{"udp"}},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Protocols: []string{"tcp"}},
	}
	h := host6(s)
	h.OwnIPs = []netip.Addr{a("198.51.100.30"), a("2001:db8:e::30")}
	text := noProblems(t, h)
	has(t, text,
		`iifname "kvbr0" ip6 saddr fd00:aa:bb:2::2 ip6 daddr ::/0 tcp dport 443 accept`,
		`iifname "kvbr0" ip6 saddr fd00:aa:bb:2::2 ip6 daddr 2001:db8:9::/48 meta l4proto udp accept`,
		`iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 0.0.0.0/0 meta l4proto tcp accept`,
		`iifname "kvbr0" ip6 daddr { ::1/128, fe80::/10, ::/128, ff00::/8, ::ffff:0:0/96, fc00::/7 } drop`,
		`iifname "kvbr0" ip6 daddr { 2001:db8:a::5, 2001:db8:e::10, fd00:aa:bb:2::1, 2001:db8:e::30 } drop`,
		`ip6 saddr fd00:aa:bb:2::/64 oifname != "kvbr0" masquerade`,
		`ip6 saddr fd00:aa:bb:2::/64 ip6 daddr fd00:aa:bb:2::/64 oifname "kvbr0" ct status dnat masquerade`)
	hasNot(t, text, "snat ip6")
	rs := parseNFT(t, text)
	out := func(dst string, proto string, port int) bool {
		o, gate := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: a(web6), daddr: a(dst), proto: proto, dport: port})
		return o || gate
	}
	for _, c := range []struct {
		dst   string
		proto string
		port  int
		want  bool
	}{
		{"2606:4700::1111", "tcp", 443, true},
		{"2606:4700::1111", "tcp", 80, false},
		{"2001:db8:9:1::1", "udp", 53, true},
		{"2001:db8:9:1::1", "tcp", 53, false},
		{"fd00:aa:bb:3::2", "tcp", 443, false}, // another host's silo: never over IPv6
		{"fe80::1", "tcp", 443, false},
		{"ff02::1", "tcp", 443, false},
		{"::ffff:203.0.113.4", "tcp", 443, false},
		{ext6, "tcp", 443, false},
		{"2001:db8:e::30", "tcp", 443, false},
	} {
		if got := out(c.dst, c.proto, c.port); got != c.want {
			t.Errorf("%s %s:%d: out %v, want %v", c.proto, c.dst, c.port, got, c.want)
		}
	}
	// From another source on its port, the grant is not its: never.
	if o, _ := rs.outFrom(t, h, pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: a("fd00:aa:bb:2::9"), daddr: a("2606:4700::1111"), proto: "tcp", dport: 443}); o {
		t.Error("a spoofed IPv6 source got out")
	}

	// egress.source on a kept IPv6 IP: SNAT for IPv6 only.
	s.EgressIPv6 = a("2001:db8:e::30")
	has(t, noProblems(t, host6(s)), `ip6 saddr fd00:aa:bb:2::2 oifname != "kvbr0" snat ip6 to 2001:db8:e::30`)

	// A silo without an IPv6 address: its IPv6 grants open nothing, and that is no problem.
	s.IP6, s.EgressIPv6 = netip.Addr{}, netip.Addr{}
	text = noProblems(t, host6(s))
	hasNot(t, text, "ip6 daddr ::/0", "2001:db8:9::/48")
}

// A lease: a closed leased port has no IPv6 rule either, and the IPv6 connections it let in are
// cut (reset), like the IPv4 ones. Held by routing: no rule, nothing cut.
func TestIPv6Leases(t *testing.T) {
	s := web(opens(5432, v1.ServicePort{}, v1.NetworkExternal))
	s.Leased, s.Closed = []string{"web"}, []string{"web"}
	text := noProblems(t, host6(s))
	hasNot(t, text, "dnat ip6", "dnat ip ")
	has(t, text,
		`oifname "kvbr0" ip6 daddr fd00:aa:bb:2::2 tcp dport 5432 ct status dnat ct original ip6 daddr 2001:db8:e::10 reject with tcp reset`,
		`iifname "kvbr0" ip6 saddr fd00:aa:bb:2::2 tcp sport 5432 ct status dnat ct original ip6 daddr 2001:db8:e::10 reject with tcp reset`,
		`oifname "kvbr0" ip daddr 10.64.2.2 tcp dport 5432 ct status dnat ct original ip daddr 198.51.100.10 reject with tcp reset`)
	// The cut is before the established accept.
	cut := strings.Index(text, "ct original ip6 daddr 2001:db8:e::10 reject")
	est := strings.Index(text, `oifname "kvbr0" ct state established,related accept`)
	if cut < 0 || est < 0 || cut > est {
		t.Fatal("the IPv6 cut is not before the established accept")
	}
	s.Closed = nil
	has(t, noProblems(t, host6(s)), "dnat ip6 to [fd00:aa:bb:2::2]:5432")
	s.Held = true
	text = noProblems(t, host6(s))
	hasNot(t, text, "dnat ip6", "reject")
}

// Revokes: allowFrom is silo to silo, which stays IPv4 (the mesh), so a revoked allowFrom flow
// is cut over IPv4 only, and nothing over IPv6 was ever open between silos to revoke.
func TestIPv6NoSiloToSiloAndRevokesStayIPv4(t *testing.T) {
	db := Silo{Key: "dev/db", IP: a("10.64.2.4"), IP6: a("fd00:aa:bb:2::4"), Tap: "kvt04", Spec: v1.SiloSpec{
		Ports:    []v1.SiloPort{{Name: "pg", Port: 5432}},
		Services: []v1.SiloService{{Ports: []v1.ServicePort{{Port: "pg", AllowFrom: []string{"web"}}}}}}}
	w := web(v1.SiloSpec{})
	prev := host6(db, w)
	prev.All = []Silo{db, w}
	cur := prev
	cdb := db
	cdb.Spec = v1.SiloSpec{Ports: db.Spec.Ports, Services: []v1.SiloService{{Ports: []v1.ServicePort{{Port: "pg"}}}}}
	cur.Local, cur.All = []Silo{cdb, w}, []Silo{cdb, w}
	rp := Remember(prev, cur)
	cur.Revoke = &rp
	text := noProblems(t, cur)
	has(t, text, "ip saddr 10.64.2.2 ip daddr 10.64.2.4 tcp dport 5432 reject with tcp reset")
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "ip6") && (strings.Contains(l, "reject") || strings.Contains(l, "5432")) {
			t.Errorf("an IPv6 rule for silo-to-silo: %s", l)
		}
	}
	rs := parseNFT(t, noProblems(t, prev))
	p := pkt{iif: w.Tap, oif: db.Tap, ether: w.MAC, saddr: w.IP6, daddr: db.IP6, proto: "tcp", dport: 5432}
	if rs.bridged(t, p) {
		t.Fatal("web reached db over IPv6 by allowFrom")
	}
	p4 := pkt{iif: w.Tap, oif: db.Tap, ether: w.MAC, saddr: w.IP, daddr: db.IP, proto: "tcp", dport: 5432}
	if !rs.bridged(t, p4) {
		t.Fatal("web doesn't reach db over IPv4: the evaluator or the rules are off")
	}
}

// The port's anti-spoof: a silo sends IPv6 from its own address (and the MAC its runtime fixed)
// only, and advertises no other address as its own (neighbour discovery's ARP). A duplicated
// IPv6 address binds neither silo's IPv6 (their IPv4 stays).
func TestIPv6PortAntiSpoof(t *testing.T) {
	w := web(v1.SiloSpec{})
	text := noProblems(t, host6(w))
	has(t, text,
		`iifname "kvt02" icmpv6 type nd-neighbor-advert icmpv6 taddr != fd00:aa:bb:2::2 drop`,
		`iifname "kvt02" ether saddr 52:4b:00:00:00:02 ip6 saddr fd00:aa:bb:2::2 accept`,
		`iifname "kvbr0" ip6 saddr fd00:aa:bb:2::/64 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept`,
		`iifname "kvbr0" ip6 daddr fd00:aa:bb:2::1 icmpv6 type echo-request accept`,
		`ip6 saddr fd00:aa:bb:2::/64 iifname != "kvbr0" drop`)
	// The advert drop is before the accept that would take it.
	if strings.Index(text, "icmpv6 taddr != fd00:aa:bb:2::2 drop") > strings.Index(text, "ip6 saddr fd00:aa:bb:2::2 accept") {
		t.Fatal("the advert drop comes after the accept")
	}
	o := Silo{Key: "dev/other", IP: a("10.64.2.3"), IP6: a(web6), Tap: "kvt03"}
	bs := Bindings([]Silo{w, o})
	if len(bs) != 2 || bs[0].IP6.IsValid() || bs[1].IP6.IsValid() || !bs[0].IP.IsValid() {
		t.Fatalf("a shared IPv6 address: %+v", bs)
	}
	// From the uplink, the silo subnet's IPv6 source is dropped whatever it goes to.
	rs := parseNFT(t, text)
	if v := rs.verdict(t, "inet forward", pkt{iif: "eth0", oif: "kvbr0", saddr: a("fd00:aa:bb:2::7"), daddr: a(web6), proto: "tcp", dport: 22}); v == "accept" {
		t.Fatal("a silo-subnet IPv6 source from the uplink was forwarded")
	}
}

// Invalid IPv6 input is reported and left out, never written: the rest of the table stands.
func TestIPv6InvalidInputIsAProblem(t *testing.T) {
	s := web(opens(443, v1.ServicePort{Sources: []string{"::ffff:192.0.2.7", "fe80::1%eth0", "2001:db8:c::/48", "192.0.2.0/24"}}, v1.NetworkExternal))
	s.EgressIPv6 = a("198.51.100.30") // IPv4 where IPv6 is wanted
	s.Egress = []v1.ParsedEgress{{Prefix: netip.MustParsePrefix("::ffff:10.62.0.0/112"), Protocols: []string{"tcp"}}}
	o := Silo{Key: "dev/out", IP: a("10.64.2.3"), IP6: a("fd00:aa:bb:9::3"), Tap: "kvt03"} // outside the subnet
	gw := Silo{Key: "dev/gw", IP: a("10.64.2.5"), IP6: a("fd00:aa:bb:2::1"), Tap: "kvt05"} // the gateway's
	ll := Silo{Key: "dev/ll", IP: a("10.64.2.6"), IP6: a("fe80::6"), Tap: "kvt06"}
	h := host6(s, o, gw, ll)
	h.InternalIPv6 = a("fe80::5")
	h.ExternalIPv6 = a("198.51.100.10")
	text, problems := Generate(h)
	for _, want := range []struct{ owner, reason string }{
		{"dev/web", "IPv4-mapped IPv6 address"},
		{"dev/web", "an address with a zone"},
		{"dev/web", "its IPv6 egress address is not a global IPv6 address"},
		{"dev/web", "a grant's IPv4-mapped IPv6 range"},
		{"dev/out", "not one in this host's IPv6 silo subnet"},
		{"dev/gw", "not one in this host's IPv6 silo subnet"},
		{"dev/ll", "not one in this host's IPv6 silo subnet"},
		{"internalIPv6", "not a global IPv6 address"},
		{"externalIPv6", "not a global IPv6 address"},
	} {
		if !hasProblem(problems, want.owner, want.reason) {
			t.Errorf("not reported: %s %q in %v", want.owner, want.reason, problems)
		}
	}
	hasNot(t, text, "::ffff:192.0.2.7", "fe80::1%", "fd00:aa:bb:9::3", "fe80::6", "fe80::5", "::ffff:10.62", "snat ip6")
	// External IPv6 was refused, so nothing opens over IPv6 on the worker; IPv4 stands.
	hasNot(t, text, "dnat ip6")
	has(t, text, "ip daddr 198.51.100.10 tcp dport 443 dnat ip to 10.64.2.2:443", "ip saddr 192.0.2.0/24 tcp dport 443")
	parseNFT(t, text) // and the evaluator takes it

	// A subnet that isn't IPv6, a gateway outside it: no IPv6 for this host, said.
	bad := host6(web(v1.SiloSpec{}))
	bad.Subnet6, bad.Gateway6 = netip.MustParsePrefix("10.64.2.0/24"), a("fd00:aa:bb:2::1")
	text, problems = Generate(bad)
	hasNot(t, text, "ip6 ")
	if !hasProblem(problems, "subnet6", "not an IPv6 silo subnet") || !hasProblem(problems, "dev/web", "no IPv6 silo subnet") {
		t.Errorf("not reported: %v", problems)
	}
	off := host6(web(v1.SiloSpec{}))
	off.Gateway6 = a("fd00:aa:bb:3::1")
	text, problems = Generate(off)
	hasNot(t, text, "echo-request accept\n    iifname \"kvbr0\" ip6 daddr fd00:aa:bb:3::1")
	if !hasProblem(problems, "gateway6", "not an address in this host's IPv6 silo subnet") {
		t.Errorf("not reported: %v", problems)
	}
}
