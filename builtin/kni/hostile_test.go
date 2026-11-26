package kni

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-009, K-036: whatever reaches the generator (an IPv6 range under IPv4-only rules, a plugin's
// "source range" with a newline and rule text in it, anything that got into the store before
// admission tightened), the text it writes is one nft takes: an entry it can't express is left out,
// fail closed (it opens nothing), it's reported, and the rest of the table is as it would be
// without it. nft itself can't run here (macOS), so nftLint is what nft would refuse in the shapes
// Rules writes; any line it doesn't know is refused.

// nftLint lists what nft would refuse in text.
func nftLint(text string) []string {
	var bad []string
	depth := 0
	for n, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case l == "":
		case strings.HasPrefix(l, "table ") && strings.HasSuffix(l, "{"):
			depth++
		case strings.HasPrefix(l, "chain ") && strings.HasSuffix(l, "{"):
			depth++
		case l == "}":
			depth--
		case strings.HasPrefix(l, "table ") || strings.HasPrefix(l, "delete table "):
			if depth != 0 {
				bad = append(bad, fmt.Sprintf("line %d: %q inside a block", n+1, l))
			}
		case strings.HasPrefix(l, "type "):
		default:
			if depth != 2 {
				bad = append(bad, fmt.Sprintf("line %d: rule outside a chain: %q", n+1, l))
				continue
			}
			if err := lintRule(tokens(l)); err != nil {
				bad = append(bad, fmt.Sprintf("line %d: %v: %q", n+1, err, l))
			}
		}
	}
	if depth != 0 {
		bad = append(bad, "unbalanced braces")
	}
	return bad
}

func lintV4(tok string) error {
	for _, it := range setItems(tok) {
		if p, err := netip.ParsePrefix(it); err == nil {
			if !p.Addr().Is4() || p.Masked() != p {
				return fmt.Errorf("%q: not an IPv4 prefix in canonical form", it)
			}
			continue
		}
		if a, err := netip.ParseAddr(it); err != nil || !a.Is4() {
			return fmt.Errorf("%q: not an IPv4 address", it)
		}
	}
	return nil
}

func lintPorts(tok string) error {
	for _, it := range setItems(tok) {
		lo, hi, isRange := strings.Cut(it, "-")
		a, err := strconv.Atoi(lo)
		b := a
		if isRange {
			b, err = strconv.Atoi(hi)
		}
		if err != nil || a < 1 || b > 65535 || a > b {
			return fmt.Errorf("%q: not a port or range", it)
		}
	}
	return nil
}

func lintIfname(tok string) error {
	for _, it := range setItems(tok) {
		n := strings.Trim(it, `"`)
		if !strings.HasPrefix(it, `"`) || !strings.HasSuffix(it, `"`) || !validIfname(strings.TrimSuffix(n, "*")) {
			return fmt.Errorf("%q: not an interface name", it)
		}
	}
	return nil
}

func lintAddrPort(s string) error {
	ap, err := netip.ParseAddrPort(s)
	if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
		return fmt.Errorf("%q: not IPv4:PORT", s)
	}
	return nil
}

// lintRule walks one rule in the grammar Rules writes.
func lintRule(r []string) error {
	opt := func(i int) int {
		if i < len(r) && r[i] == "!=" {
			return i + 1
		}
		return i
	}
	need := func(i, n int) error {
		if i+n > len(r) {
			return fmt.Errorf("rule ends early")
		}
		return nil
	}
	for i := 0; i < len(r); {
		var err error
		switch r[i] {
		case "iifname", "oifname":
			j := opt(i + 1)
			if err = need(j, 1); err == nil {
				err = lintIfname(r[j])
			}
			i = j + 1
		case "ip":
			if err = need(i, 3); err == nil && r[i+1] != "saddr" && r[i+1] != "daddr" {
				err = fmt.Errorf("ip %s", r[i+1])
			}
			j := opt(i + 2)
			if err == nil {
				if err = need(j, 1); err == nil {
					err = lintV4(r[j])
				}
			}
			i = j + 1
		case "tcp", "udp":
			if err = need(i, 3); err == nil {
				if r[i+1] != "dport" && r[i+1] != "sport" {
					err = fmt.Errorf("%s %s", r[i], r[i+1])
				} else {
					err = lintPorts(r[i+2])
				}
			}
			i += 3
		case "meta":
			switch {
			case i+2 < len(r) && r[i+1] == "l4proto" && (r[i+2] == "tcp" || r[i+2] == "udp"):
				i += 3
			case i+3 < len(r) && r[i+1] == "mark" && r[i+2] == "set":
				_, err = strconv.ParseUint(r[i+3], 0, 32)
				i += 4
			default:
				err, i = fmt.Errorf("meta %v", r[i+1:]), len(r)
			}
		case "ether":
			switch {
			case i+2 < len(r) && r[i+1] == "type" && r[i+2] == "arp":
				i += 3
			case i+2 < len(r) && r[i+1] == "saddr":
				j := opt(i + 2)
				if _, e := parseMAC(r[j]); e != nil {
					err = e
				}
				i = j + 1
			default:
				err, i = fmt.Errorf("ether %v", r[i+1:]), len(r)
			}
		case "arp":
			if err = need(i, 4); err == nil {
				j := opt(i + 3)
				switch r[i+2] {
				case "ip":
					err = lintV4(r[j])
				case "ether":
					_, err = parseMAC(r[j])
				default:
					err = fmt.Errorf("arp saddr %s", r[i+2])
				}
				i = j + 1
			}
		case "icmp":
			if i+2 >= len(r) || r[i+1] != "type" || r[i+2] != "echo-request" {
				err = fmt.Errorf("icmp %v", r[i+1:])
			}
			i += 3
		case "ct":
			switch {
			case i+2 < len(r) && r[i+1] == "status" && r[i+2] == "dnat":
				i += 3
			case i+2 < len(r) && r[i+1] == "state" && r[i+2] == "established,related":
				i += 3
			case i+4 < len(r) && r[i+1] == "original" && r[i+2] == "ip" && r[i+3] == "daddr":
				err = lintV4(r[i+4])
				i += 5
			case i+3 < len(r) && r[i+1] == "original" && r[i+2] == "proto-dst":
				err = lintPorts(r[i+3])
				i += 4
			default:
				err, i = fmt.Errorf("ct %v", r[i+1:]), len(r)
			}
		case "accept", "drop", "masquerade":
			if i != len(r)-1 {
				err = fmt.Errorf("tokens after %s", r[i])
			}
			i = len(r)
		case "reject":
			if strings.Join(r[i:], " ") != "reject with tcp reset" {
				err = fmt.Errorf("reject %v", r[i+1:])
			}
			i = len(r)
		case "redirect":
			if len(r) != i+3 || r[i+1] != "to" || !strings.HasPrefix(r[i+2], ":") {
				err = fmt.Errorf("redirect %v", r[i+1:])
			} else {
				err = lintPorts(strings.TrimPrefix(r[i+2], ":"))
			}
			i = len(r)
		case "snat":
			if len(r) != i+4 || r[i+1] != "ip" || r[i+2] != "to" {
				err = fmt.Errorf("snat %v", r[i+1:])
			} else {
				err = lintV4(r[i+3])
			}
			i = len(r)
		case "dnat":
			if i+3 >= len(r) || r[i+1] != "ip" || r[i+2] != "to" {
				err, i = fmt.Errorf("dnat %v", r[i+1:]), len(r)
				break
			}
			if r[i+3] != "numgen" {
				err = lintAddrPort(r[i+3])
				if len(r) != i+4 {
					err = fmt.Errorf("tokens after dnat")
				}
				i = len(r)
				break
			}
			for _, it := range setItems(r[len(r)-1]) { // 0 : A . P
				f := strings.Fields(it)
				if len(f) != 5 {
					err = fmt.Errorf("numgen map item %q", it)
					break
				}
				if err = lintAddrPort(f[2] + ":" + f[4]); err != nil {
					break
				}
			}
			i = len(r)
		default:
			err, i = fmt.Errorf("token %q", r[i]), len(r)
		}
		if err != nil {
			return err
		}
	}
	switch v := r[len(r)-1]; {
	case v == "accept", v == "drop", v == "masquerade", v == "reset", strings.HasPrefix(v, ":"), strings.Contains(strings.Join(r, " "), " snat ip to "), strings.Contains(strings.Join(r, " "), " dnat ip to "):
	default:
		return fmt.Errorf("no verdict")
	}
	return nil
}

func parseMAC(s string) (string, error) {
	f := strings.Split(s, ":")
	if len(f) != 6 {
		return "", fmt.Errorf("%q: not a MAC", s)
	}
	for _, x := range f {
		if _, err := strconv.ParseUint(x, 16, 8); err != nil || len(x) != 2 {
			return "", fmt.Errorf("%q: not a MAC", s)
		}
	}
	return s, nil
}

// hostileSources are what may reach a source list from the store or a plugin.
var hostileSources = []string{"::/0", "2001:db8::/32", "2001:db8::1", "::ffff:192.0.2.7", "192.0.2.7\n    flush ruleset", "1.2.3.4 } accept; {",
	"host.example.com", "10.0.0.0/33", "", " 192.0.2.8", "192.0.2.256", "0x0a000001", "10.0.0.1/8\"", "*"}

func hostileHost() Host {
	good := Silo{Key: "dev/good", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{Sources: []string{"192.0.2.0/25"}}, v1.NetworkInternal)}
	allBad := Silo{Key: "dev/bad", IP: a("10.64.2.3"), Tap: "kvt03", Spec: opens(9090, v1.ServicePort{Sources: hostileSources}, v1.NetworkInternal)}
	mixed := Silo{Key: "dev/mixed", IP: a("10.64.2.4"), Tap: "kvt04", Spec: opens(7070, v1.ServicePort{Sources: append([]string{"203.0.113.0/24"}, hostileSources...)}, v1.NetworkInternal)}
	lb := Silo{Key: "dev/lb", IP: a("10.64.2.5"), Tap: "kvt05", Spec: func() v1.SiloSpec {
		return opens(6060, v1.ServicePort{}, lbWay)
	}(), NodePorts: []v1.NodePort{{Name: "web", Port: 6060, NodePort: 30001}}, SourceRanges: hostileSources}
	v6 := Silo{Key: "dev/v6", IP: a("fd00::5"), Tap: "kvt06", Spec: opens(5050, v1.ServicePort{}, v1.NetworkInternal)}
	addrs := Silo{Key: "dev/addrs", IP: a("10.64.2.7"), Tap: "kvt07", Spec: opens(4040, v1.ServicePort{}, lbWay),
		LoadBalancerIP: a("2001:db8::7"), EgressIP: a("2001:db8::8"), GatePorts: []v1.PortRange{{From: 0, To: 70000}, {From: 443, To: 443}},
		Egress: []v1.ParsedEgress{{Prefix: netip.MustParsePrefix("2001:db8::/32"), Protocols: []string{"tcp"}}, {Prefix: netip.MustParsePrefix("192.0.2.0/24"), Protocols: []string{"sctp\n flush ruleset"}}}}
	badPort := Silo{Key: "dev/badport", IP: a("10.64.2.8"), Tap: "kvt08", Spec: opens(70000, v1.ServicePort{}, v1.NetworkInternal)}
	h := host(good, allBad, mixed, lb, v6, addrs, badPort)
	h.GatePort = 15001
	h.ExternalIP = a("2001:db8::10")
	h.Endpoint = a("169.254.42.1")
	h.All = append(append([]Silo(nil), h.Local...), Silo{Key: "dev/far6", IP: a("fd00::9")})
	h.Services = []Service{{Key: "dev/svc", ClusterIP: a("10.65.0.3"), SourceRanges: hostileSources,
		Ports: []ServicePort{{Proto: "tcp", Port: 80, NodePort: 30002, Targets: []Target{{IP: a("10.64.2.2"), Port: 8080, Local: true}, {IP: a("fd00::2"), Port: 8080}}}}}}
	return h
}

func TestHostileEntriesNeverBreakTheTable(t *testing.T) {
	h := hostileHost()
	text, problems := Generate(h)
	if bad := nftLint(text); len(bad) > 0 {
		t.Fatalf("nft would refuse the table:\n%s\n%s", strings.Join(bad, "\n"), text)
	}
	rs := parseNFT(t, text)
	// The good silo is unaffected: open to its sources, closed to the rest.
	if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: a("192.0.2.7"), daddr: propInternal, proto: "tcp", dport: 8080}); !ok {
		t.Errorf("the good silo's port is closed:\n%s", text)
	}
	// Every entry of bad's was dropped: closed to everyone (an empty list must not mean "anyone").
	for _, c := range append([]netip.Addr{a("192.0.2.7"), a("1.2.3.4"), a("10.0.0.5")}, propClients...) {
		if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: c, daddr: propInternal, proto: "tcp", dport: 9090}); ok {
			t.Errorf("%s reached bad's port, whose every source was dropped", c)
		}
		if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: c, daddr: propInternal, proto: "tcp", dport: 30001}); ok {
			t.Errorf("%s reached lb's node port, whose every source range was dropped", c)
		}
		if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: c, daddr: propInternal, proto: "tcp", dport: 30002}); ok {
			t.Errorf("%s reached the Service's node port, whose every source range was dropped", c)
		}
	}
	// mixed keeps its good entry and only it.
	if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: a("203.0.113.4"), daddr: propInternal, proto: "tcp", dport: 7070}); !ok {
		t.Error("mixed's good source was dropped with its bad ones")
	}
	if _, ok := rs.reaches(t, h, pkt{iif: "eth0", saddr: a("192.0.2.7"), daddr: propInternal, proto: "tcp", dport: 7070}); ok {
		t.Error("mixed reached from a source it didn't list")
	}
	// Reported, per silo and port, with the reason.
	want := map[string]bool{"dev/bad web": false, "dev/mixed web": false, "dev/lb web": false, "dev/v6 ": false, "dev/addrs ": false, "dev/badport web": false, "dev/svc ": false}
	for _, p := range problems {
		k := p.Owner + " " + p.Port
		if _, ok := want[k]; ok {
			want[k] = true
		}
		if p.Reason == "" {
			t.Errorf("problem without a reason: %+v", p)
		}
		if strings.ContainsAny(p.Entry, "\n\r") {
			t.Errorf("a problem's entry holds a line break (it goes into a status message): %q", p.Entry)
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("no problem reported for %q in %+v", k, problems)
		}
	}
	for _, p := range problems {
		if p.Owner == "dev/good" {
			t.Errorf("the good silo was blamed: %+v", p)
		}
	}
}

// Removing the hostile entries changes nothing else: the table is the one the clean view gives.
func TestHostileEntriesOnlyRemoveThemselves(t *testing.T) {
	clean := host(Silo{Key: "dev/good", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{Sources: []string{"192.0.2.0/25"}}, v1.NetworkInternal)})
	dirty := clean
	dirty.Local = append([]Silo(nil), clean.Local...)
	dirty.Local[0].Spec = opens(8080, v1.ServicePort{Sources: append([]string{"192.0.2.0/25"}, hostileSources...)}, v1.NetworkInternal)
	want, _ := Generate(clean)
	got, problems := Generate(dirty)
	if got != want {
		t.Errorf("hostile sources changed more than themselves:\n%s\nwant\n%s", got, want)
	}
	if len(problems) == 0 {
		t.Error("nothing reported")
	}
	// A prefix with host bits set is the network it names, written canonically.
	n := host(Silo{Key: "dev/n", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{Sources: []string{"10.0.0.5/24"}}, v1.NetworkInternal)})
	if text := Rules(n); !strings.Contains(text, "ip saddr 10.0.0.0/24 ") {
		t.Errorf("10.0.0.5/24 not written as 10.0.0.0/24:\n%s", text)
	}
}

// Every user-controlled position, fuzzed: the text is always one nft takes, and the good silo's
// port is always there.
func FuzzRulesTakeAnyEntry(f *testing.F) {
	for _, s := range hostileSources {
		f.Add(s, s, s, "kvt09", "52:4b:00:00:00:01", 80, 443, "TCP")
	}
	f.Add("10.0.0.0/8", "192.0.2.1", "203.0.113.0/24", "kvt\"09", "zz", 0, 70000, "sctp")
	f.Fuzz(func(t *testing.T, src, lbRange, svcRange, tap, mac string, port, nodePort int, proto string) {
		good := Silo{Key: "dev/good", IP: a("10.64.2.2"), Tap: "kvt02", Spec: opens(8080, v1.ServicePort{}, v1.NetworkInternal)}
		x := Silo{Key: "dev/x", IP: a("10.64.2.9"), Tap: tap, MAC: mac,
			Spec: v1.SiloSpec{Ports: []v1.SiloPort{{Name: "p", Port: port, Protocol: proto}},
				Services: []v1.SiloService{
					service(v1.NetworkInternal, v1.ServicePort{Port: "p", Sources: []string{src}}),
					{Name: "x-lb", Type: v1.ServiceLoadBalancer, LoadBalancer: &v1.LoadBalancerSpec{Provider: "plugin"}, Ports: []v1.ServicePort{{Port: "p", Sources: []string{src}}}}}},
			NodePorts: []v1.NodePort{{Name: "p", Port: port, NodePort: nodePort}}, SourceRanges: []string{lbRange, src}}
		if a, err := netip.ParseAddr(src); err == nil {
			x.LoadBalancerIP, x.EgressIP = a, a
		}
		h := host(good, x)
		h.Services = []Service{{Key: "dev/s", ClusterIP: a("10.65.0.3"), SourceRanges: []string{svcRange},
			Ports: []ServicePort{{Proto: strings.ToLower(proto), Port: port, NodePort: nodePort, Targets: []Target{{IP: a("10.64.2.9"), Port: port, Local: true}}}}}}
		text, _ := Generate(h)
		if bad := nftLint(text); len(bad) > 0 {
			t.Fatalf("nft would refuse:\n%s\n%s", strings.Join(bad, "\n"), text)
		}
		if !strings.Contains(text, "ip daddr 10.0.0.5 tcp dport 8080 dnat ip to 10.64.2.2:8080") {
			t.Fatalf("the good silo's port is gone:\n%s", text)
		}
	})
}
