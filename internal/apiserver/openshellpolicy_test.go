package apiserver

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func TestOpenShellPolicyAdmission(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	if err := admitJSON(t, s, "OpenShellPolicy", objectOf(t, "OpenShellPolicy", nil)); err != nil {
		t.Fatalf("a policy of one public name: %v", err)
	}

	canon := `{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"Example.COM.","port":443},{"host":"8.8.8.8/32","port":53}],"binaries":[{"path":"/usr/bin/curl"}]}]}}`
	k, _ := v1.Lookup("OpenShellPolicy")
	obj, err := decodeStrict([]byte(canon), k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.admit("OpenShellPolicy", obj); err != nil {
		t.Fatal(err)
	}
	eps := obj.(*v1.OpenShellPolicy).Spec.NetworkPolicies[0].Endpoints
	if eps[0].Host != "example.com" || eps[1].Host != "8.8.8.8" {
		t.Fatalf("hosts stored as %q %q", eps[0].Host, eps[1].Host)
	}

	unknown := `{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"example.com","port":443,"extra":1}]}]}}`
	if err := admitJSON(t, s, "OpenShellPolicy", []byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: %v", err)
	}

	bad := []struct{ body, want string }{
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"10.64.2.5","port":443}]}]}}`, "10.64.0.0/16"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"127.0.0.1","port":443}]}]}}`, "loopback"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"169.254.169.254","port":80}]}]}}`, "link-local"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"10.1.2.3","port":443}]}]}}`, "hosts are names or public addresses"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"8.8.8.8/24","port":443}]}]}}`, "not a range"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"2001:db8::1","port":443}]}]}}`, "IPv6 comes later"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"example.com","port":443,"path":"../x"}]}]}}`, "path"},
		{`{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"example.com","port":443}],"binaries":[{"path":"curl"}]}]}}`, "binaries path"},
		{policyWithEndpoints(17), "1 to 16"},
		{policyWithBinaries(17), "1 to 16"},
		{policyWithRules(33), "1 to 32"},
	}
	for _, c := range bad {
		err := admitJSON(t, s, "OpenShellPolicy", []byte(c.body))
		var ae *apiError
		if !errors.As(err, &ae) || ae.code != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), c.want) {
			t.Errorf("want 422 containing %q, got %v", c.want, err)
		}
	}
}

func policyWithEndpoints(n int) string {
	var eps []string
	for i := 0; i < n; i++ {
		eps = append(eps, fmt.Sprintf(`{"host":"h%d.example.com","port":443}`, i))
	}
	return `{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[` + strings.Join(eps, ",") + `]}]}}`
}

func policyWithBinaries(n int) string {
	var bins []string
	for i := 0; i < n; i++ {
		bins = append(bins, fmt.Sprintf(`{"path":"/bin/b%d"}`, i))
	}
	return `{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"example.com","port":443}],"binaries":[` + strings.Join(bins, ",") + `]}]}}`
}

func policyWithRules(n int) string {
	var rules []string
	for i := 0; i < n; i++ {
		rules = append(rules, fmt.Sprintf(`{"name":"r%d","endpoints":[{"host":"example.com","port":443}]}`, i))
	}
	return `{"apiVersion":"kevaso/v1","kind":"OpenShellPolicy","metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[` + strings.Join(rules, ",") + `]}}`
}

func TestOpenShellPoliciesOnlyOnOpenShell(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	ok := []string{
		`{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"openshell","container":{"image":"ubuntu-24.04"},"openshellPolicies":["web"]}}`,
		`{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"openshell-container","container":{"image":"ubuntu-24.04"},"openshellPolicies":["web"]}}`,
		`{"apiVersion":"kevaso/v1","kind":"SiloSet","metadata":{"name":"set","namespace":"d"},"spec":{"instances":1,"template":{"runtime":"openshell","container":{"image":"ubuntu-24.04"},"openshellPolicies":["web"]}}}`,
	}
	for _, body := range ok {
		kind := "Silo"
		if strings.Contains(body, `"kind":"SiloSet"`) {
			kind = "SiloSet"
		}
		if err := admitJSON(t, s, kind, []byte(body)); err != nil {
			t.Errorf("openshell naming a policy: %v\n%s", err, body)
		}
	}
	no := []struct{ kind, body string }{
		{"Silo", `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"docker","container":{"image":"nginx:1.27"},"openshellPolicies":["web"]}}`},
		{"Silo", `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"podman","container":{"image":"nginx:1.27"},"openshellPolicies":["web"]}}`},
		{"Silo", `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"cloud-hypervisor","vm":{"image":"ubuntu-24.04"},"openshellPolicies":["web"]}}`},
		{"SiloSet", `{"apiVersion":"kevaso/v1","kind":"SiloSet","metadata":{"name":"set","namespace":"d"},"spec":{"instances":1,"template":{"runtime":"docker","container":{"image":"nginx:1.27"},"openshellPolicies":["web"]}}}`},
	}
	for _, c := range no {
		err := admitJSON(t, s, c.kind, []byte(c.body))
		var ae *apiError
		if !errors.As(err, &ae) || ae.code != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "openshellPolicies is only for runtime openshell or openshell-container") {
			t.Errorf("%s: %v", c.kind, err)
		}
		if c.kind == "SiloSet" && !strings.Contains(err.Error(), "template: ") {
			t.Errorf("siloset: %v; want the template prefix", err)
		}
	}
	var names []string
	for i := 0; i < v1.MaxOpenShellPolicyNames+1; i++ {
		names = append(names, fmt.Sprintf("%q", fmt.Sprintf("p%d", i)))
	}
	over := `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"openshell","container":{"image":"ubuntu-24.04"},"openshellPolicies":[` + strings.Join(names, ",") + `]}}`
	if err := admitJSON(t, s, "Silo", []byte(over)); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Fatalf("33 names: %v", err)
	}
}
