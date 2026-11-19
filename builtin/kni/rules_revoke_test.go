package kni

import (
	"net/netip"
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

func TestRemovingAGrantResetsOnlyThatPrefix(t *testing.T) {
	api := siloAt("dev/api", "10.64.2.2", v1.SiloSpec{},
		v1.ParsedEgress{Prefix: netip.MustParsePrefix("1.1.1.1/32"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}},
		v1.ParsedEgress{Prefix: netip.MustParsePrefix("9.9.9.9/32"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}},
	)
	prev := host(api)
	cur := prev
	cur.Local = []Silo{siloAt("dev/api", "10.64.2.2", v1.SiloSpec{},
		v1.ParsedEgress{Prefix: netip.MustParsePrefix("9.9.9.9/32"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}},
	)}
	cur.Revoke = &prev
	rules := Rules(cur)
	if !strings.Contains(rules, `iifname "kvbr0" ip saddr 10.64.2.2 ip daddr 1.1.1.1/32 tcp dport 443 reject with tcp reset`) {
		t.Fatalf("1.1.1.1 was not reset:\n%s", rules)
	}
	if strings.Contains(rules, "ip daddr 9.9.9.9/32 tcp dport 443 reject") {
		t.Fatalf("9.9.9.9 is still granted and was reset:\n%s", rules)
	}
	if !strings.Contains(rules, "ip daddr 9.9.9.9/32 tcp dport 443 accept") {
		t.Fatalf("9.9.9.9's accept is gone:\n%s", rules)
	}
}

func TestNarrowingAGrantDoesNotResetTheRemainder(t *testing.T) {
	wide := v1.ParsedEgress{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}}
	left := v1.ParsedEgress{Prefix: netip.MustParsePrefix("1.1.1.1/32"), Protocols: []string{"tcp"}, Ports: []v1.PortRange{{From: 443, To: 443}}}
	prev := host(siloAt("dev/api", "10.64.2.2", v1.SiloSpec{}, wide))
	cur := prev
	cur.Local = []Silo{siloAt("dev/api", "10.64.2.2", v1.SiloSpec{}, left)}
	cur.Revoke = &prev
	rules := Rules(cur)
	if !strings.Contains(rules, "ip daddr 0.0.0.0/0 ip daddr != 1.1.1.1/32 tcp dport 443 reject with tcp reset") {
		t.Fatalf("the wide grant was not cut around the remainder:\n%s", rules)
	}
	if strings.Contains(rules, "ip daddr 1.1.1.1/32 tcp dport 443 reject") {
		t.Fatalf("the remainder was reset:\n%s", rules)
	}
}
