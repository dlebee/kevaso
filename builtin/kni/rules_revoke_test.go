package kni

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func siloAt(key, ip string, spec v1.SiloSpec, egress ...v1.ParsedEgress) Silo {
	return Silo{Key: key, IP: a(ip), Spec: spec, Egress: egress}
}

func TestRemovingAllowFromResetsOnlyThatFlow(t *testing.T) {
	spec := opens(8080, v1.ServicePort{AllowFrom: []string{"worker", "batch"}})
	worker := siloAt("dev/worker", "10.64.2.3", v1.SiloSpec{})
	batch := siloAt("dev/batch", "10.64.2.4", v1.SiloSpec{})
	api := siloAt("dev/api", "10.64.2.2", spec)
	prev := host(api, worker, batch)
	prev.All = []Silo{api, worker, batch}
	cur := prev
	cur.Local = []Silo{siloAt("dev/api", "10.64.2.2", opens(8080, v1.ServicePort{AllowFrom: []string{"batch"}})), worker, batch}
	cur.Revoke = &prev
	rules := Rules(cur)
	if !strings.Contains(rules, "ip saddr 10.64.2.3 ip daddr 10.64.2.2 tcp dport 8080 reject with tcp reset") {
		t.Fatalf("worker's flow was not reset:\n%s", rules)
	}
	if !strings.Contains(rules, "ip saddr 10.64.2.2 ip daddr 10.64.2.3 tcp sport 8080 reject with tcp reset") {
		t.Fatalf("the reply was not reset:\n%s", rules)
	}
	if strings.Contains(rules, "ip saddr 10.64.2.4 ip daddr 10.64.2.2 tcp dport 8080 reject") {
		t.Fatalf("batch is still allowed and was reset:\n%s", rules)
	}
	if !strings.Contains(rules, "ip saddr 10.64.2.4 ip daddr 10.64.2.2 tcp dport 8080 accept") {
		t.Fatalf("batch's accept is gone:\n%s", rules)
	}
}

// A grant of every port, then only 443, still accepts 443. The previous table's grant is what
// the rules are asked to reset. It adds no cut: a new connection on 443 follows the grant loaded
// now, and a port that grant no longer names does not.
func TestNarrowingAGrantTo443StillAcceptsPort443(t *testing.T) {
	wide, err := v1.EgressRule{To: "203.0.113.0/24"}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	left, err := v1.EgressRule{To: "203.0.113.0/24", Ports: []string{"443"}}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	silo := func(e v1.ParsedEgress) Silo {
		return Silo{Key: "dev/api", IP: a("10.64.2.2"), Tap: "kvt02", MAC: "02:00:00:00:00:02", Egress: []v1.ParsedEgress{e}}
	}
	prev := host(silo(wide))
	cur := host(silo(left))
	cur.Revoke = &prev
	rs := parseNFT(t, Rules(cur))
	pktTo := func(port int) pkt {
		s := silo(left)
		return pkt{iif: s.Tap, oif: "eth0", ether: s.MAC, saddr: s.IP, daddr: a("203.0.113.9"), proto: "tcp", dport: port}
	}
	if out, gate := rs.outFrom(t, cur, pktTo(443)); !out || gate {
		t.Fatalf("port 443 after the grant was narrowed to it: out %v gate %v", out, gate)
	}
	if out, gate := rs.outFrom(t, cur, pktTo(80)); out || gate {
		t.Fatalf("port 80 is no longer granted and was accepted: out %v gate %v", out, gate)
	}
}

// The memory used to reset a later table keeps an allowFrom entry that was removed, and does not
// keep a grant.
func TestRememberKeepsAllowFromAndDropsGrants(t *testing.T) {
	wide, err := v1.EgressRule{To: "203.0.113.0/24"}.Parse()
	if err != nil {
		t.Fatal(err)
	}
	spec := opens(8080, v1.ServicePort{AllowFrom: []string{"worker"}})
	prev := host(siloAt("dev/api", "10.64.2.2", spec, wide), siloAt("dev/worker", "10.64.2.3", v1.SiloSpec{}))
	cur := prev
	cur.Local = []Silo{
		siloAt("dev/api", "10.64.2.2", opens(8080, v1.ServicePort{}), wide),
		siloAt("dev/worker", "10.64.2.3", v1.SiloSpec{}),
	}
	got := Remember(prev, cur)
	api := got.Local[0]
	if len(api.Egress) != 0 {
		t.Fatalf("a grant was remembered: %+v", api.Egress)
	}
	open := api.Spec.Open()
	if len(open) != 1 || len(open[0].AllowFrom) != 1 || open[0].AllowFrom[0] != "worker" {
		t.Fatalf("the removed allowFrom was not kept: %+v", api.Spec)
	}
}

// bridgeChain is one base chain of table bridge kevaso, as Generate wrote it.
type bridgeChain struct {
	hook  string
	rules []string
}

// parseBridgeTable reads table bridge kevaso: each base chain's hook and its rules, in order.
func parseBridgeTable(t *testing.T, text string) map[string]bridgeChain {
	t.Helper()
	out := map[string]bridgeChain{}
	inTable := false
	depth := 0
	var name string
	var cur bridgeChain
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		if !inTable {
			if l == "table bridge kevaso {" {
				inTable, depth = true, 1
			}
			continue
		}
		switch {
		case strings.HasPrefix(l, "chain ") && strings.HasSuffix(l, "{"):
			name = strings.TrimSuffix(strings.TrimPrefix(l, "chain "), " {")
			cur = bridgeChain{}
			depth++
		case strings.HasPrefix(l, "type "):
			cur.hook = nftHook(l)
			if cur.hook == "" {
				t.Fatalf("chain %s has no hook: %q", name, l)
			}
		case l == "}":
			depth--
			if name != "" {
				out[name] = cur
				name = ""
			}
			if depth == 0 {
				inTable = false
			}
		case name != "" && l != "":
			cur.rules = append(cur.rules, l)
		}
	}
	if !inTable && len(out) == 0 {
		t.Fatalf("no bridge table in:\n%s", text)
	}
	return out
}

func nftHook(typeLine string) string {
	f := strings.Fields(typeLine)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "hook" {
			return strings.TrimSuffix(f[i+1], ";")
		}
	}
	return ""
}

func ruleVerdict(rule string) string {
	f := strings.Fields(rule)
	if len(f) == 0 {
		return ""
	}
	if f[len(f)-1] == "accept" {
		return "accept"
	}
	if strings.Contains(rule, "reject") {
		return "reject"
	}
	return ""
}

// A same-host allowFrom cut uses reject for TCP. The bridge family accepts reject only in
// prerouting and input; reject in forward makes nft refuse the host's whole silo firewall, so
// every later silo on that host stays not ready. The cut also has to be ahead of the per-port
// accepts: those accept every frame from the silo's address, and would keep the flow.
func TestBridgeRejectOnlyInPreroutingOrInput(t *testing.T) {
	worker := siloAt("dev/worker", "10.64.2.3", v1.SiloSpec{})
	worker.Tap, worker.MAC = "kvt03", "02:00:00:00:00:03"
	api := siloAt("dev/api", "10.64.2.2", opens(8080, v1.ServicePort{AllowFrom: []string{"worker"}}))
	api.Tap, api.MAC = "kvt02", "02:00:00:00:00:02"
	prev := host(api, worker)
	prev.All = []Silo{api, worker}
	cur := prev
	closed := api
	closed.Spec = opens(8080, v1.ServicePort{})
	cur.Local = []Silo{closed, worker}
	cur.All = []Silo{closed, worker}
	cur.Revoke = &prev

	rules, problems := Generate(cur)
	if len(problems) != 0 {
		t.Fatalf("problems: %+v", problems)
	}
	chains := parseBridgeTable(t, rules)
	for _, name := range []string{"prerouting", "forward"} {
		ch, ok := chains[name]
		if !ok || ch.hook != name {
			t.Fatalf("bridge chain %s hook %q, want %s\n%s", name, ch.hook, name, rules)
		}
	}
	want := []string{
		"ip saddr 10.64.2.3 ip daddr 10.64.2.2 tcp dport 8080 reject with tcp reset",
		"ip saddr 10.64.2.2 ip daddr 10.64.2.3 tcp sport 8080 reject with tcp reset",
	}
	seen := map[string]bool{}
	for name, ch := range chains {
		firstAccept, lastReject := -1, -1
		for i, rule := range ch.rules {
			switch ruleVerdict(rule) {
			case "accept":
				if firstAccept < 0 {
					firstAccept = i
				}
			case "reject":
				lastReject = i
				if ch.hook != "prerouting" && ch.hook != "input" {
					t.Errorf("bridge chain %s (hook %s) rejects, which this family refuses there: %s", name, ch.hook, rule)
				}
				for _, w := range want {
					if rule == w {
						seen[w] = ch.hook == "prerouting" || ch.hook == "input"
					}
				}
			}
		}
		if lastReject >= 0 && firstAccept >= 0 && lastReject > firstAccept {
			t.Errorf("bridge chain %s accepts a frame before it rejects one, so the cut never runs\n%s", name, strings.Join(ch.rules, "\n"))
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("revoked same-host flow is not reset in bridge prerouting or input: %s", w)
		}
	}
}
