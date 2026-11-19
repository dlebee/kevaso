package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

func TestAHostMustBeAssignedToItsNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAPINames([]string{"api.cluster.example"})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	for _, n := range []string{"shop", "payments"} {
		if err := c.Create(ctx, ns(n)); err != nil {
			t.Fatal(err)
		}
	}
	class := &v1.IngressClass{TypeMeta: tm("IngressClass"), ObjectMeta: meta.ObjectMeta{Name: "public"},
		Spec: v1.IngressClassSpec{Controller: v1.IngressController{Driver: "nginx", Silo: "edge", Namespace: "shop"},
			Hosts: []v1.HostAssignment{{Host: "shop.example.com", Namespaces: []string{"shop"}},
				{Host: "api.cluster.example", Namespaces: []string{"payments"}}}}}
	if err := c.Create(ctx, class); err != nil {
		t.Fatal(err)
	}
	ing := func(ns, name, host string) *v1.Ingress {
		return &v1.Ingress{TypeMeta: tm("Ingress"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1.IngressSpec{IngressClass: "public", Hosts: []string{host},
				Rules: []v1.IngressRule{{Path: "/", Service: v1.IngressTarget{Name: "web", Port: "http"}}}}}
	}
	if err := c.Create(ctx, ing("shop", "web", "shop.example.com")); err != nil {
		t.Fatal(err)
	}
	err = c.Create(ctx, ing("payments", "steal", "shop.example.com"))
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "IngressClass.spec.hosts") || !strings.Contains(err.Error(), "kvoadm ingress assign public --host shop.example.com=payments") {
		t.Fatalf("unassigned ingress: %v", err)
	}
	cert := func(ns, name, host string) *v1.Certificate {
		return &v1.Certificate{TypeMeta: tm("Certificate"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns},
			Spec: v1.CertificateSpec{Hosts: []string{host}, Issuer: "internal-ca", SecretName: name}}
	}
	if err := c.Create(ctx, cert("payments", "own", "api.payments.kevaso")); err != nil {
		t.Fatal(err)
	}
	err = c.Create(ctx, cert("payments", "theirs", "api.shop.kevaso"))
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "cluster admin") {
		t.Fatalf("another namespace's service name: %v", err)
	}
	err = c.Create(ctx, cert("payments", "api", "api.cluster.example"))
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "API server") {
		t.Fatalf("API server name: %v", err)
	}
}

func TestRenewKeepsTheCaller(t *testing.T) {
	e := setupAuth(t)
	if err := e.admin.Create(e.ctx, host("hv2")); err != nil {
		t.Fatal(err)
	}
	tok, err := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	c := e.tlsClient(t, &cred)
	_, csr, err := client.NewKeyAndCSR("evil")
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Certificate string `json:"certificate"`
	}
	body := map[string]string{"csr": string(csr), "host": "evil", "name": "mallory", "role": "cluster-admin"}
	if err := c.Call(e.ctx, http.MethodPost, "/renew", body, &resp); err != nil {
		t.Fatal(err)
	}
	id, err := pki.IdentityOfPEM([]byte(resp.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if id.Type != "host" || id.Name != "hv2" || id.Role != "worker" {
		t.Fatalf("renewed as %s %s %s", id.Type, id.Name, id.Role)
	}
	if err := e.admin.Delete(e.ctx, "Host", "", "hv2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(e.ctx, http.MethodPost, "/renew", body, &resp); code(err) != http.StatusUnauthorized {
		t.Fatalf("a removed host renewed: %v", err)
	}
}
