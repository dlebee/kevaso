package integration

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/guest"
	"kevaso.com/core/sdk/kri"
)

// The ingress path through the API: publishing on a public class is its own permission, and only
// the class's controller silo gets routes, certificates and ACME answers over the broker.
func TestIngress(t *testing.T) {
	c := newCluster(t)
	for _, n := range []string{"kevaso-system", "payments"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	if err := c.admin.Create(c.ctx, &v1.IngressClass{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "IngressClass"},
		ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Public: true, Controller: v1.SiloRef{Silo: "ingress-public", Namespace: "kevaso-system"}}}); err != nil {
		t.Fatal(err)
	}
	place := func(name, ns string, svc *v1.Service) *v1.Silo {
		t.Helper()
		s := silo(name, ns)
		s.Spec.Service = svc
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctrl := place("ingress-public", "kevaso-system", nil)
	other := place("bystander", "kevaso-system", nil)
	place("api", "payments", &v1.Service{Ports: []v1.ServicePort{{Name: "http", Port: 8080}}})

	ing := func(name string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Ingress"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "payments"},
			Spec: v1.IngressSpec{IngressClass: "public", Hosts: []string{"api.example.com"}, Rules: []v1.IngressRule{{Path: "/", Silo: v1.IngressTarget{Name: "api", Port: "http"}}}}}
	}
	// Who may publish on a public class.
	_ = c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}})
	_ = c.admin.Create(c.ctx, &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "payments"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}})
	if err := c.as(t, "ed").Create(c.ctx, ing("by-ed")); status(err) != http.StatusForbidden || !strings.Contains(err.Error(), "publish-public") {
		t.Fatalf("editor publishing on a public class: %v", err)
	}
	if err := c.as(t, "ada").Create(c.ctx, ing("api")); err != nil {
		t.Fatalf("admin publishing: %v", err)
	}
	bad := ing("bad")
	bad.Spec.IngressClass = "nope"
	if err := c.admin.Create(c.ctx, bad); status(err) != http.StatusUnprocessableEntity {
		t.Fatalf("a class that doesn't exist: %v", err)
	}

	// The certificate as the controller would leave it (the certificate controller has its own tests).
	if err := c.admin.Create(c.ctx, &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: "api-tls", Namespace: "payments"}, Spec: v1.SecretSpec{Value: []byte("-----BEGIN CERTIFICATE-----\n…")}}); err != nil {
		t.Fatal(err)
	}

	dir, _ := os.MkdirTemp("/tmp", "kvg")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ch := channels{dir}
	hv1 := &agent.Broker{Client: c.host(t, "hv1")}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	for _, s := range []*v1.Silo{ctrl, other} {
		if err := hv1.Ensure(ctx, ch, kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}); err != nil {
			t.Fatal(err)
		}
	}
	r, err := guest.Call(ctx, ch.dialer(ctrl.UID), client.BrokerRequest{Op: client.OpIngress})
	if err != nil || r.Ingress == nil {
		t.Fatalf("controller: %v", err)
	}
	if len(r.Ingress.Routes) != 1 || r.Ingress.Routes[0].Backend != "api.payments.kevaso:8080" || !r.Ingress.Routes[0].TLS || r.Ingress.Routes[0].Host != "api.example.com" {
		t.Fatalf("routes %+v", r.Ingress.Routes)
	}
	if len(r.Ingress.Certs) != 1 || !strings.HasPrefix(string(r.Ingress.Certs[0].Bundle), "-----BEGIN CERTIFICATE") {
		t.Fatalf("certs %+v", r.Ingress.Certs)
	}
	if _, err := guest.Call(ctx, ch.dialer(other.UID), client.BrokerRequest{Op: client.OpIngress}); err == nil || !strings.Contains(err.Error(), "isn't the controller") {
		t.Fatalf("a silo that controls no class: %v", err)
	}
}
