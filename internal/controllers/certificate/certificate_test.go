package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/sdk/kcc"
)

func TestDesiredCertificate(t *testing.T) {
	public := &v1.IngressClass{ObjectMeta: meta.ObjectMeta{Name: "public"}, Spec: v1.IngressClassSpec{Public: true, Issuer: "pebble"}}
	private := &v1.IngressClass{ObjectMeta: meta.ObjectMeta{Name: "private"}}
	ing := &v1.Ingress{ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments"}, Spec: v1.IngressSpec{Hosts: []string{"b.example.com", "a.example.com"}}}

	c := DesiredCertificate(ing, public)
	if c.Name != "api-tls" || c.Spec.SecretName != "api-tls" || c.Spec.Issuer != "pebble" || c.Spec.Hosts[0] != "a.example.com" || c.Labels[LabelIngress] != "api" {
		t.Fatalf("public: %+v", c)
	}
	if c := DesiredCertificate(ing, &v1.IngressClass{Spec: v1.IngressClassSpec{Public: true}}); c.Spec.Issuer != IssuerLetsEncrypt {
		t.Errorf("public without an issuer: %s", c.Spec.Issuer)
	}
	if c := DesiredCertificate(ing, private); c.Spec.Issuer != IssuerInternal {
		t.Errorf("private class: %s, want internal-ca", c.Spec.Issuer)
	}
	ing.Spec.TLS.Mode = v1.TLSNone
	if DesiredCertificate(ing, private) != nil {
		t.Error("tls none got a certificate")
	}
}

func TestRenewAfter(t *testing.T) {
	nb := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if got := RenewAfter(nb, nb.Add(90*24*time.Hour)); !got.Equal(nb.Add(60 * 24 * time.Hour)) {
		t.Fatalf("90-day certificate renews at %s, want after 60 days", got)
	}
}

func TestInternalCAAndBundle(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cc, err := BuiltinCertControllers(nil, nil, ca, clock.Real{}.Now, nil).Get("internal-ca")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hosts := []string{"api.payments.kevaso"}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := cc.Issue(context.Background(), kcc.Request{Issuer: "internal-ca", Hosts: hosts, CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Bundle(chain, key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ParseBundle(bundle)
	if err != nil {
		t.Fatalf("the bundle isn't a certificate and its key: %v", err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: "api.payments.kevaso"}); err != nil {
		t.Fatalf("not valid for the host under the cluster CA: %v", err)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) < 89*24*time.Hour {
		t.Errorf("lifetime %s", leaf.NotAfter.Sub(leaf.NotBefore))
	}
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 7: time.Hour, 50: time.Hour} {
		if got := Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}
