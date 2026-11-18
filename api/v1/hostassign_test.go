package v1

import "testing"

func TestHostAssignmentMatchesOneLabel(t *testing.T) {
	a := HostAssignment{Host: "*.shop.example.com", Namespaces: []string{"shop"}}
	if !a.Allows("shop", "a.shop.example.com") {
		t.Fatal("one label under the suffix was refused")
	}
	if a.Allows("shop", "shop.example.com") || a.Allows("shop", "b.a.shop.example.com") || a.Allows("other", "a.shop.example.com") {
		t.Fatal("the suffix matched the apex, two labels, or another namespace")
	}
	c := &IngressClass{Spec: IngressClassSpec{Hosts: []HostAssignment{{Host: "api.example.com", Namespaces: []string{"payments"}}}}}
	if c.AllowsHost("payments", "API.example.com.") != true || c.AllowsHost("shop", "api.example.com") {
		t.Fatal("exact host assignment")
	}
	if (&IngressClass{}).AllowsHost("payments", "api.example.com") {
		t.Fatal("a class with no assignments granted a host")
	}
}

func TestAServiceNameIsOnlyTheNamespacesOwn(t *testing.T) {
	if !InternalServiceHost("api.payments.kevaso", "payments", "") || !InternalServiceHost("api.payments.mesh.kevaso", "payments", "kevaso") {
		t.Fatal("the namespace's own service names were refused")
	}
	if InternalServiceHost("api.shop.kevaso", "payments", "kevaso") {
		t.Fatal("another namespace's service name was accepted")
	}
	if InternalServiceHost("api.payments.kevaso.extra", "payments", "kevaso") {
		t.Fatal("a name with an extra label was accepted")
	}
}

func TestAnAPINameIsRefusedEvenWhenAssigned(t *testing.T) {
	class := &IngressClass{Spec: IngressClassSpec{Hosts: []HostAssignment{{Host: "api.example.com", Namespaces: []string{"payments"}}}}}
	if why := CertificateHostProblem("api.example.com", "payments", "kevaso", []*IngressClass{class}, []string{"api.example.com"}); why == "" {
		t.Fatal("an API server name was allowed because it was assigned")
	}
	if why := IngressHostProblem("api.example.com", "payments", class, []string{"api.example.com"}); why == "" {
		t.Fatal("an ingress for an API server name was allowed")
	}
}

func TestOpenShellArchiveIsNotAnImage(t *testing.T) {
	spec := SiloSpec{Runtime: "openshell", Container: &ContainerSource{Image: "var/lib/x/foo.tar"}}
	if len(SourceProblems(spec, nil)) == 0 {
		t.Fatal("a rootfs archive was accepted as an image")
	}
	ok := SiloSpec{Runtime: "openshell", Container: &ContainerSource{Image: "ghcr.io/acme/api:v1"}}
	if p := SourceProblems(ok, nil); len(p) != 0 {
		t.Fatalf("a registry reference was refused: %v", p)
	}
}
