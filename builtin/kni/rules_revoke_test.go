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
