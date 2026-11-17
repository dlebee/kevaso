package openshell

import (
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// OpenShell reads enforcement on the endpoint and defaults it to audit, so a protocol, path or
// access limit is logged and the request is still allowed. Kevaso writes enforce on every such
// endpoint. A plain host:port grant is a connection allow and stays without the field.
func TestInspectedEndpointsAreEnforced(t *testing.T) {
	plain := PolicyYAML(kri.Policy{Egress: []kri.Endpoint{{Host: "plain.example.com", Port: 80}}})
	if strings.Contains(plain, "enforcement:") {
		t.Fatalf("a host:port grant is a connection allow:\n%s", plain)
	}
	got := PolicyYAML(kri.Policy{
		Egress: []kri.Endpoint{
			{Host: "api.anthropic.com", Port: 443},
			{Host: "plain.example.com", Port: 443},
		},
		Credentials: []kri.Credential{{Host: "api.anthropic.com"}},
		Rules: []kri.NetworkRule{
			{Name: "osp_web", Endpoints: []kri.RuleEndpoint{{
				Host: "example.com", Port: 443, Protocol: "rest", Path: "/", Access: "read-only",
			}}},
			{Name: "osp_rest", Endpoints: []kri.RuleEndpoint{{Host: "r.example.com", Port: 443, Protocol: "rest"}}},
			{Name: "osp_path", Endpoints: []kri.RuleEndpoint{{Host: "p.example.com", Port: 443, Path: "/v1"}}},
			{Name: "osp_rw", Endpoints: []kri.RuleEndpoint{{Host: "w.example.com", Port: 443, Access: "read-write"}}},
			{Name: "osp_plain", Endpoints: []kri.RuleEndpoint{{Host: "z.example.com", Port: 80}}},
		},
	})
	want := basePolicy + "network_policies:\n" +
		"  kv_0:\n    name: kv_0\n    endpoints:\n      - host: \"api.anthropic.com\"\n        port: 443\n        protocol: rest\n        access: read-write\n        enforcement: enforce\n    binaries:\n      - path: \"/**\"\n" +
		"  kv_1:\n    name: kv_1\n    endpoints:\n      - host: \"plain.example.com\"\n        port: 443\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_web:\n    name: osp_web\n    endpoints:\n      - host: \"example.com\"\n        port: 443\n        protocol: rest\n        path: \"/\"\n        access: read-only\n        enforcement: enforce\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_rest:\n    name: osp_rest\n    endpoints:\n      - host: \"r.example.com\"\n        port: 443\n        protocol: rest\n        enforcement: enforce\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_path:\n    name: osp_path\n    endpoints:\n      - host: \"p.example.com\"\n        port: 443\n        path: \"/v1\"\n        enforcement: enforce\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_rw:\n    name: osp_rw\n    endpoints:\n      - host: \"w.example.com\"\n        port: 443\n        access: read-write\n        enforcement: enforce\n    binaries:\n      - path: \"/**\"\n" +
		"  osp_plain:\n    name: osp_plain\n    endpoints:\n      - host: \"z.example.com\"\n        port: 80\n    binaries:\n      - path: \"/**\"\n"
	if got != want {
		t.Fatalf("policy file:\n%s\nwant:\n%s", got, want)
	}
	prof := ProfileYAML(kri.ID{Namespace: "dev", Name: "box", UID: "1"}, kri.Credential{Name: "k", Env: "K", Host: "api.example.com", Header: "X-Api-Key"})
	if !strings.Contains(prof, "enforcement: enforce\n") {
		t.Fatalf("provider profile:\n%s", prof)
	}
}
