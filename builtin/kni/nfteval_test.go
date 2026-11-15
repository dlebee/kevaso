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
	chains   map[string][][]string // "inet prerouting", "inet forward", "bridge forward", …
	policies map[string]string     // each base chain's policy (accept | drop)
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
	rs := nftRuleset{chains: map[string][][]string{}, policies: map[string]string{}}
	family, chain := "", ""
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(l, "type "):
			_, pol, ok := strings.Cut(l, "policy ")
			pol = strings.TrimSuffix(strings.TrimSpace(pol), ";")
			if !ok || (pol != "accept" && pol != "drop") {
				t.Fatalf("chain %s without a policy: %q", chain, l)
			}
			rs.policies[chain] = pol
		case l == "" || strings.HasPrefix(l, "delete table "):
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

// pkt is the first packet of a new connection (no ct state established), or an ARP frame.
type pkt struct {
	iif, oif     string
	saddr, daddr netip.Addr // an IPv6 saddr/daddr makes it an IPv6 packet
	proto        string     // tcp | udp | arp (then saddr is the ARP sender's address)
	// ether is the frame's source MAC ("" where it doesn't matter: never matches a MAC rule).
	ether string
	dport int
	sport int // 0: an ephemeral port (40000)
	// set by DNAT
	dnat      bool
	origDaddr netip.Addr
	origDport int
	// set by meta mark set
	mark uint32
}

func (p pkt) family() string {
	switch {
	case p.proto == "arp":
		return "arp"
	case p.saddr.Is6() || p.daddr.Is6():
		return "ip6"
	}
	return "ip"
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

// match reports whether r matches p and its verdict (with its arguments). A `meta mark set` in a
// rule that matches so far sets p.mark (the caller keeps it when the verdict is accept).
func match(t *testing.T, r []string, p *pkt) (bool, []string) {
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
		case "ip", "ip6":
			field := r[i+1]
			n, j := neg(i + 2)
			a := p.saddr
			if field == "daddr" {
				a = p.daddr
			} else if field != "saddr" {
				t.Fatalf("%s %s in %v", r[i], field, r)
			}
			// `ip saddr` matches IPv4 packets only (nft adds the protocol check), `ip6 saddr`
			// IPv6 only: a packet of the other family doesn't match, negated or not.
			if p.family() != r[i] || addrIn(t, a, r[j]) == n {
				ok = false
			}
			i = j + 1
		case "ether":
			switch r[i+1] {
			case "saddr":
				n, j := neg(i + 2)
				if (p.ether != "" && strings.EqualFold(p.ether, r[j])) == n {
					ok = false
				}
				i = j + 1
			case "type":
				if r[i+2] != p.family() {
					ok = false
				}
				i += 3
			default:
				t.Fatalf("ether %s in %v", r[i+1], r)
			}
		case "arp":
			// arp saddr ip [!=] A | arp saddr ether [!=] M
			if r[i+1] != "saddr" {
				t.Fatalf("arp %s in %v", r[i+1], r)
			}
			n, j := neg(i + 3)
			var in bool
			switch r[i+2] {
			case "ip":
				in = p.family() == "arp" && p.saddr.Is4() && addrIn(t, p.saddr, r[j])
			case "ether":
				in = p.family() == "arp" && p.ether != "" && strings.EqualFold(p.ether, r[j])
			default:
				t.Fatalf("arp saddr %s in %v", r[i+2], r)
			}
			if p.family() != "arp" || in == n {
				ok = false
			}
			i = j + 1
		case "tcp", "udp":
			if p.family() == "arp" {
				ok = false
			}
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
			switch {
			case r[i+1] == "l4proto":
				if p.proto != r[i+2] {
					ok = false
				}
				i += 3
			case r[i+1] == "mark" && r[i+2] == "set":
				m, err := strconv.ParseUint(r[i+3], 0, 32)
				if err != nil {
					t.Fatalf("meta mark set %q", r[i+3])
				}
				if ok {
					p.mark = uint32(m)
				}
				i += 4
			case r[i+1] == "mark":
				n, j := neg(i + 2)
				m, err := strconv.ParseUint(r[j], 0, 32)
				if err != nil {
					t.Fatalf("meta mark %q", r[j])
				}
				if (p.mark == uint32(m)) == n {
					ok = false
				}
				i = j + 1
			default:
				t.Fatalf("meta %s in %v", r[i+1], r)
			}
		case "icmp":
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
		ok, v := match(t, r, &p)
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

// verdict is the first accept/drop/reject in chain for p, else the chain's policy.
func (rs nftRuleset) verdict(t *testing.T, chain string, p pkt) string {
	v, _ := rs.verdictMark(t, chain, p)
	return v
}

// verdictMark is verdict, with the packet as it leaves the chain (its mark).
func (rs nftRuleset) verdictMark(t *testing.T, chain string, p pkt) (string, pkt) {
	for _, r := range rs.chains[chain] {
		q := p
		if ok, v := match(t, r, &q); ok {
			switch v[0] {
			case "accept", "drop", "reject":
				return v[0], q
			}
			p = q
		}
	}
	pol, ok := rs.policies[chain]
	if !ok {
		t.Fatalf("no chain %s", chain)
	}
	return pol, p
}

// fromPort is a frame arriving on bridge port p.iif: what the bridge's prerouting hook does with
// it, before it is bridged to another port or passed up to the host.
func (rs nftRuleset) fromPort(t *testing.T, p pkt) (pkt, bool) {
	v, q := rs.verdictMark(t, "bridge prerouting", p)
	return q, v == "accept"
}

// toHost sends a packet from a silo (arriving on tap p.iif) to the host itself (the gateway, the
// local endpoint): the bridge's prerouting, then the inet input chain, as arriving on the bridge.
func (rs nftRuleset) toHost(t *testing.T, h Host, p pkt) bool {
	p, ok := rs.fromPort(t, p)
	if !ok {
		return false
	}
	p.iif = h.Bridge
	return rs.verdict(t, "inet input", p) == "accept"
}

// outFrom sends a packet from a silo (on tap p.iif) through the host to outside the cluster
// (routed out of p.oif): bridge prerouting, inet prerouting (redirect: to the gate), forward.
func (rs nftRuleset) outFrom(t *testing.T, h Host, p pkt) (out, toGate bool) {
	p, ok := rs.fromPort(t, p)
	if !ok {
		return false, false
	}
	p.iif = h.Bridge
	p, redirected := rs.prerouting(t, p)
	if redirected {
		return false, true
	}
	return rs.verdict(t, "inet forward", p) == "accept", false
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

// bridged sends p between two taps on the bridge (silo to silo on one host): the bridge's
// prerouting on the port it came in on, then its forward chain.
func (rs nftRuleset) bridged(t *testing.T, p pkt) bool {
	p, ok := rs.fromPort(t, p)
	return ok && rs.verdict(t, "bridge forward", p) == "accept"
}
