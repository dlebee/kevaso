package kni

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// A small evaluator for the nft text Rules writes: enough of nft's grammar to send one new
// connection's first packet through prerouting (DNAT) and a forward chain, so the properties
// below judge what the rules do rather than what they say. It is strict: a token it doesn't know
// fails the test, so a rule shape Rules starts writing must be taught here before it is trusted.

type nftRuleset struct {
	chains map[string][][]string // "inet prerouting", "inet forward", "bridge forward", …
}

// tokens splits one rule, keeping { … } sets (and numgen maps) as one token "{a,b}".
func tokens(line string) []string {
	var out []string
	f := strings.Fields(line)
	for i := 0; i < len(f); i++ {
		if f[i] != "{" {
			out = append(out, f[i])
			continue
		}
		var inner []string
		for i++; i < len(f) && f[i] != "}"; i++ {
			inner = append(inner, strings.TrimSuffix(f[i], ","))
		}
		out = append(out, "{"+strings.Join(inner, ",")+"}")
	}
	return out
}

func parseNFT(t *testing.T, text string) nftRuleset {
	t.Helper()
	rs := nftRuleset{chains: map[string][][]string{}}
	family, chain := "", ""
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case l == "" || strings.HasPrefix(l, "type ") || strings.HasPrefix(l, "delete table "):
		case strings.HasPrefix(l, "table ") && strings.HasSuffix(l, "{"):
			family = strings.Fields(l)[1]
		case strings.HasPrefix(l, "table "):
		case strings.HasPrefix(l, "chain ") && strings.HasSuffix(l, "{"):
			chain = family + " " + strings.Fields(l)[1]
		case l == "}":
			if chain != "" {
				chain = ""
			} else {
				family = ""
			}
		default:
			if chain == "" {
				t.Fatalf("rule outside a chain: %q", l)
			}
			rs.chains[chain] = append(rs.chains[chain], tokens(l))
		}
	}
	return rs
}

// pkt is the first packet of a new connection (no ct state established).
type pkt struct {
	iif, oif     string
	saddr, daddr netip.Addr
	proto        string // tcp | udp
	dport        int
	sport        int // 0: an ephemeral port (40000)
	// set by DNAT
	dnat      bool
	origDaddr netip.Addr
	origDport int
}

func globMatch(pat, name string) bool {
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pat, "*"))
	}
	return pat == name
}

func setItems(tok string) []string {
	if strings.HasPrefix(tok, "{") {
		return strings.Split(strings.Trim(tok, "{}"), ",")
	}
	return []string{tok}
}

func addrIn(t *testing.T, a netip.Addr, tok string) bool {
	for _, it := range setItems(tok) {
		if p, err := netip.ParsePrefix(it); err == nil {
			if p.Contains(a) {
				return true
			}
			continue
		}
		b, err := netip.ParseAddr(it)
		if err != nil {
			t.Fatalf("not an address or prefix: %q", it)
		}
		if a == b {
			return true
		}
	}
	return false
}

func portIn(t *testing.T, n int, tok string) bool {
	for _, it := range setItems(tok) {
		lo, hi, isRange := strings.Cut(it, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			t.Fatalf("not a port: %q", it)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				t.Fatalf("not a port range: %q", it)
			}
		}
		if n >= a && n <= b {
			return true
		}
	}
	return false
}

// match reports whether r matches p and its verdict (with its arguments).
func match(t *testing.T, r []string, p pkt) (bool, []string) {
	t.Helper()
	ok := true
	neg := func(i int) (bool, int) {
		if i < len(r) && r[i] == "!=" {
			return true, i + 1
		}
		return false, i
	}
	for i := 0; i < len(r); {
		switch r[i] {
		case "iifname", "oifname":
			n, j := neg(i + 1)
			v := p.iif
			if r[i] == "oifname" {
				v = p.oif
			}
			in := false
			for _, it := range setItems(r[j]) {
				in = in || globMatch(strings.Trim(it, `"`), v)
			}
			if in == n {
				ok = false
			}
			i = j + 1
		case "ip":
			field := r[i+1]
			n, j := neg(i + 2)
			a := p.saddr
			if field == "daddr" {
				a = p.daddr
			} else if field != "saddr" {
				t.Fatalf("ip %s in %v", field, r)
			}
			if addrIn(t, a, r[j]) == n {
				ok = false
			}
			i = j + 1
		case "tcp", "udp":
			n := p.dport
			switch r[i+1] {
			case "dport":
			case "sport":
				if n = p.sport; n == 0 {
					n = 40000
				}
			default:
				t.Fatalf("%s %s in %v", r[i], r[i+1], r)
			}
			if p.proto != r[i] || !portIn(t, n, r[i+2]) {
				ok = false
			}
			i += 3
		case "meta":
			if r[i+1] != "l4proto" {
				t.Fatalf("meta %s in %v", r[i+1], r)
			}
			if p.proto != r[i+2] {
				ok = false
			}
			i += 3
		case "icmp", "ether", "arp":
			return false, nil // not modelled: never a TCP/UDP packet
		case "ct":
			switch r[i+1] {
			case "status":
				if r[i+2] != "dnat" {
					t.Fatalf("ct status %s", r[i+2])
				}
				ok = ok && p.dnat
				i += 3
			case "state":
				ok = false // new connections only
				i += 3
			case "original":
				switch r[i+2] {
				case "ip":
					ok = ok && p.dnat && addrIn(t, p.origDaddr, r[i+4])
					i += 5
				case "proto-dst":
					n, _ := strconv.Atoi(r[i+3])
					ok = ok && p.dnat && p.origDport == n
					i += 4
				default:
					t.Fatalf("ct original %s", r[i+2])
				}
			default:
				t.Fatalf("ct %s", r[i+1])
			}
		case "accept", "drop", "reject", "dnat", "snat", "masquerade", "redirect":
			return ok, r[i:]
		default:
			t.Fatalf("token %q not understood in %v", r[i], r)
		}
	}
	t.Fatalf("rule without a verdict: %v", r)
	return false, nil
}

// prerouting applies the first DNAT (or redirect) that matches. redirected: to the host itself.
func (rs nftRuleset) prerouting(t *testing.T, p pkt) (out pkt, redirected bool) {
	for _, r := range rs.chains["inet prerouting"] {
		ok, v := match(t, r, p)
		if !ok {
			continue
		}
		switch v[0] {
		case "redirect":
			return p, true
		case "dnat":
			// dnat ip to A:P | dnat ip to numgen random mod N map {0 : A . P,…} (the first target)
			to := v[3]
			if to == "numgen" {
				first := setItems(v[len(v)-1])[0]
				parts := strings.Fields(first) // "0" ":" A "." P
				to = parts[2] + ":" + parts[4]
			}
			ap, err := netip.ParseAddrPort(to)
			if err != nil {
				t.Fatalf("dnat target %q", to)
			}
			p.dnat, p.origDaddr, p.origDport = true, p.daddr, p.dport
			p.daddr, p.dport = ap.Addr(), int(ap.Port())
			return p, false
		}
	}
	return p, false
}

// verdict is the first accept/drop/reject in chain for p ("accept": the policy).
func (rs nftRuleset) verdict(t *testing.T, chain string, p pkt) string {
	for _, r := range rs.chains[chain] {
		if ok, v := match(t, r, p); ok {
			switch v[0] {
			case "accept", "drop", "reject":
				return v[0]
			}
		}
	}
	return "accept"
}

// reaches sends p (as it arrives on p.iif) through the host: it reaches a silo (its address and
// port after translation) when it's routed onto the bridge and forward accepts it.
func (rs nftRuleset) reaches(t *testing.T, h Host, p pkt) (netip.AddrPort, bool) {
	p, redirected := rs.prerouting(t, p)
	if redirected || !h.Subnet.Contains(p.daddr) {
		return netip.AddrPort{}, false
	}
	p.oif = h.Bridge
	if rs.verdict(t, "inet forward", p) != "accept" {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(p.daddr, uint16(p.dport)), true
}

// bridged sends p between two taps on the bridge (silo to silo on one host).
func (rs nftRuleset) bridged(t *testing.T, p pkt) bool {
	return rs.verdict(t, "bridge forward", p) == "accept"
}
