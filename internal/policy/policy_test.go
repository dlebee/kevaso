package policy

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/openshell"
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
	p, problems := For(s, grants, nil, inj)
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
	if p, _ := For(s, grants, nil, inj); !p.Credentials[0].Bearer {
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
	got := strings.Join(Check(s, []*v1.Grant{bad}, nil), "\n")
	for _, want := range []string{"address range", "needs ports", "at most 16", "deliver broker", "sign isn't available", `format "Token {{value}}"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !SelfEnforced("openshell-container") || SelfEnforced("cloud-hypervisor") {
		t.Error("SelfEnforced")
	}
}

// A credential that needs a person's yes can't be handed to a runtime that injects by itself: it's
// left out, and the problem says why (design §8.7).
func TestApprovalInjectionsStayOutOfSelfEnforcedPolicies(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "agent"}, Spec: v1.SiloSpec{Runtime: "openshell", Grants: []string{"admin"}}}
	grants := []*v1.Grant{grant("admin", v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "gh-admin", Deliver: v1.DeliverInject,
		To: &v1.InjectTarget{Host: "api.github.com"}, Approval: &v1.ApprovalRule{Required: true}}}})}
	p, problems := For(s, grants, nil, []client.Injection{{Host: "api.github.com", Header: "Authorization", Format: "Bearer {{value}}", Raw: []byte("x"), Secret: "gh-admin", Approval: true}})
	if len(p.Credentials) != 0 || len(problems) != 1 || !strings.Contains(problems[0], "approval") {
		t.Fatalf("credentials %v, problems %v", p.Credentials, problems)
	}
	if got := Check(s, grants, nil); len(got) != 1 || !strings.Contains(got[0], "approval") {
		t.Fatalf("Check = %v", got)
	}
}

// Grants and OpenShellPolicies are one file: grant rules stay kv_N, in host order, and each
// OpenShell rule is osp_<policy>_<rule>, in the silo's list order then the object's order.
// Nothing of either is the same deny-all. A name with no object is left out.
func TestGrantsAndOpenShellPoliciesAreOneFile(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "box"},
		Spec: v1.SiloSpec{Runtime: "openshell", Grants: []string{"web"}, OpenShellPolicies: []string{"b", "gone", "a"}}}
	grants := []*v1.Grant{grant("web", v1.GrantSpec{Egress: []v1.EgressRule{{To: "b.example.com"}, {To: "a.example.com"}}})}
	policies := []*v1.OpenShellPolicy{
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "a"}, Spec: v1.OpenShellPolicySpec{NetworkPolicies: []v1.OpenShellNetworkPolicy{{
			Name: "web", Endpoints: []v1.OpenShellEndpoint{{Host: "example.com", Port: 443, Protocol: "rest", Path: "/", Access: v1.AccessReadOnly}},
		}}}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "b"}, Spec: v1.OpenShellPolicySpec{NetworkPolicies: []v1.OpenShellNetworkPolicy{
			{Name: "z", Endpoints: []v1.OpenShellEndpoint{{Host: "z.example.com", Port: 443}}, Binaries: []v1.OpenShellBinary{{Path: "/usr/bin/curl"}}},
			{Name: "y", Endpoints: []v1.OpenShellEndpoint{{Host: "y.example.com", Port: 80}, {Host: "y.example.com", Port: 443, Path: "/v1"}}},
		}}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "other", Name: "b"}},
	}
	p, problems := For(s, grants, policies, nil)
	if len(problems) != 0 {
		t.Fatal(problems)
	}
	if len(p.Rules) != 3 || p.Rules[0].Name != "osp_b_z" || p.Rules[1].Name != "osp_b_y" || p.Rules[2].Name != "osp_a_web" {
		t.Fatalf("rules %v", p.Rules)
	}
	if len(p.Rules[1].Endpoints) != 2 || p.Rules[1].Endpoints[0].Port != 80 || p.Rules[1].Endpoints[1].Path != "/v1" {
		t.Fatalf("endpoints reordered: %+v", p.Rules[1].Endpoints)
	}
	got := openshell.PolicyYAML(p)
	want := openshell.PolicyYAML(kri.Policy{}) + "network_policies:\n" +
		"  kv_0:\n    name: kv_0\n    endpoints:\n      - host: \"a.example.com\"\n        port: 443\n    binaries:\n      - path: \"/**\"\n" +
		"  kv_1:\n    name: kv_1\n    endpoints:\n      - host: \"b.example.com\"\n        port: 443\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_b_z:\n    name: osp_b_z\n    endpoints:\n      - host: \"z.example.com\"\n        port: 443\n    binaries:\n      - path: \"/usr/bin/curl\"\n" +
		"  osp_b_y:\n    name: osp_b_y\n    endpoints:\n      - host: \"y.example.com\"\n        port: 80\n      - host: \"y.example.com\"\n        port: 443\n        path: \"/v1\"\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_a_web:\n    name: osp_a_web\n    endpoints:\n      - host: \"example.com\"\n        port: 443\n        protocol: rest\n        path: \"/\"\n        access: read-only\n    binaries:\n      - path: \"/**\"\n"
	if got != want {
		t.Fatalf("policy file:\n%s\nwant:\n%s", got, want)
	}
	empty, _ := For(&v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "box"}, Spec: v1.SiloSpec{Runtime: "openshell"}}, nil, nil, nil)
	if yaml := openshell.PolicyYAML(empty); yaml != openshell.PolicyYAML(kri.Policy{}) || strings.Contains(yaml, "network_policies") {
		t.Fatalf("no grants and no policies:\n%s", yaml)
	}
	missing, _ := For(s, nil, nil, nil)
	if yaml := openshell.PolicyYAML(missing); strings.Contains(yaml, "network_policies") {
		t.Fatalf("a listed name with no object was rendered:\n%s", yaml)
	}
}
