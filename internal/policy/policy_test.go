package policy

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

func grant(name string, spec v1.GrantSpec) *v1.Grant {
	return &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: name}, Spec: spec}
}

func TestFor(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "agent"}, Spec: v1.SiloSpec{Runtime: "openshell", Grants: []string{"web", "anthropic"}}}
	grants := []*v1.Grant{
		grant("web", v1.GrantSpec{Egress: []v1.EgressRule{
			{To: "api.github.com"}, {To: "*.npmjs.org", Ports: []string{"443", "8443"}}, {To: "203.0.113.7/32", Ports: []string{"5432"}},
		}}),
		grant("anthropic", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "anthropic-key", Deliver: v1.DeliverInject, Env: "ANTHROPIC_API_KEY",
			To: &v1.InjectTarget{Host: "api.anthropic.com", Header: "x-api-key", Format: "{{value}}"}}}}),
	}
	inj := []client.Injection{{Host: "api.anthropic.com", Header: "x-api-key", Format: "{{value}}", Env: "ANTHROPIC_API_KEY", Raw: []byte("sk"), Secret: "anthropic-key", Version: 3}}
	p, problems := For(s, grants, inj)
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	want := []kri.Endpoint{{Host: "*.npmjs.org", Port: 443}, {Host: "*.npmjs.org", Port: 8443}, {Host: "203.0.113.7", Port: 5432}, {Host: "api.anthropic.com", Port: 443}, {Host: "api.github.com", Port: 443}}
	if len(p.Egress) != len(want) {
		t.Fatalf("egress %v", p.Egress)
	}
	for i := range want {
		if p.Egress[i] != want[i] {
			t.Errorf("egress[%d] = %v, want %v", i, p.Egress[i], want[i])
		}
	}
	if len(p.Credentials) != 1 || p.Credentials[0].Bearer || p.Credentials[0].Env != "ANTHROPIC_API_KEY" || p.Credentials[0].Version != 3 {
		t.Fatalf("credentials %+v", p.Credentials)
	}
	inj[0].Header, inj[0].Format = "Authorization", "Bearer {{value}}"
	if p, _ := For(s, grants, inj); !p.Credentials[0].Bearer {
		t.Error("Authorization: Bearer isn't bearer style")
	}
}

func TestCheck(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "agent"}, Spec: v1.SiloSpec{Runtime: "openshell", Grants: []string{"bad"}}}
	bad := grant("bad", v1.GrantSpec{
		Egress: []v1.EgressRule{
			{To: "0.0.0.0/0", Ports: []string{"30303"}, Protocols: []string{"tcp", "udp"}}, // a range, and UDP
			{To: "198.51.100.9"}, // a single address, but every port
			{To: "198.51.100.9", Ports: []string{"30000-30100"}}, // too many ports
		},
		Secrets: []v1.GrantSecret{
			{Name: "db"}, // broker
			{Name: "k", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "api.x.com", Format: "Token {{value}}"}},
		},
		Operations: &v1.GrantOperations{Sign: &v1.SignOperation{KeyRef: "key"}},
	})
	got := strings.Join(Check(s, []*v1.Grant{bad}), "\n")
	for _, want := range []string{"address range", "needs ports", "at most 16", "deliver broker", "sign isn't available", `format "Token {{value}}"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !SelfEnforced("openshell-container") || SelfEnforced("cloud-hypervisor") {
		t.Error("SelfEnforced")
	}
}
