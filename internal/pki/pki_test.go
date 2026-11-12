package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("home", now)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func parseCert(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIdentityURIRoundTrip(t *testing.T) {
	for _, id := range []Identity{
		{Type: "host", Name: "hv1", Role: "worker"},
		{Type: "host", Name: "cp-1", Role: "control-plane"},
		{Type: "user", Name: "admin", Role: "cluster-admin"},
	} {
		got, err := ParseIdentity(id.URI())
		if err != nil || got != id {
			t.Errorf("%v → %s → %v, %v", id, id.URI(), got, err)
		}
	}
	for _, bad := range []string{
		"https://host/hv1/role/worker", "kevaso://host/hv1", "kevaso://host/hv1/role/worker/extra",
		"kevaso://robot/hv1/role/worker", "kevaso://host/HV1/role/worker", "kevaso://host/hv1/rule/worker",
	} {
		u, _ := url.Parse(bad)
		if _, err := ParseIdentity(u); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestSignCSRUsesOnlyTheAllowedIdentity(t *testing.T) {
	ca := mustCA(t)
	// The requester asks to be a control plane; the caller only allows worker on hv2.
	_, csr, err := NewKeyAndCSR(Identity{Type: "host", Name: "hv9", Role: "control-plane"})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.SignCSR(csr, Identity{Type: "host", Name: "hv2", Role: "worker"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := parseCert(t, certPEM)
	id, err := IdentityOf(c)
	if err != nil || id != (Identity{Type: "host", Name: "hv2", Role: "worker"}) {
		t.Fatalf("issued identity %v, %v", id, err)
	}
	if len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.URIs) != 1 {
		t.Fatalf("extra SANs leaked into the certificate: %v %v %v", c.DNSNames, c.IPAddresses, c.URIs)
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("issued cert doesn't verify against the CA: %v", err)
	}
	if c.NotAfter.Sub(now) > time.Hour {
		t.Fatalf("cert lives until %v, want 1h", c.NotAfter)
	}
}

func TestSignCSRRejects(t *testing.T) {
	ca := mustCA(t)
	_, csr, _ := NewKeyAndCSR(Identity{Type: "host", Name: "hv1", Role: "worker"})
	if _, err := ca.SignCSR([]byte("not pem"), Identity{Type: "host", Name: "hv1", Role: "worker"}, now, time.Hour); err == nil {
		t.Error("garbage CSR accepted")
	}
	if _, err := ca.SignCSR(csr, Identity{Type: "host", Name: "Bad Name", Role: "worker"}, now, time.Hour); err == nil {
		t.Error("invalid identity accepted")
	}
	// A CSR whose signature doesn't match (tampered) is refused.
	b, _ := pem.Decode(csr)
	b.Bytes[len(b.Bytes)-1] ^= 0xff
	if _, err := ca.SignCSR(pem.EncodeToMemory(b), Identity{Type: "host", Name: "hv1", Role: "worker"}, now, time.Hour); err == nil {
		t.Error("tampered CSR accepted")
	}
}

func TestOtherCAIsRejected(t *testing.T) {
	ca, rogue := mustCA(t), mustCA(t)
	_, csr, _ := NewKeyAndCSR(Identity{Type: "user", Name: "admin", Role: "cluster-admin"})
	certPEM, _ := rogue.SignCSR(csr, Identity{Type: "user", Name: "admin", Role: "cluster-admin"}, now, time.Hour)
	c := parseCert(t, certPEM)
	if _, err := c.Verify(x509.VerifyOptions{Roots: ca.Pool(), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("a certificate from another CA verified")
	}
}

func TestServerCertAndSaveLoad(t *testing.T) {
	ca := mustCA(t)
	dir := t.TempDir()
	if err := ca.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(dir)
	if err != nil || !loaded.Cert.Equal(ca.Cert) {
		t.Fatalf("load: %v", err)
	}
	sc, err := loaded.ServerCert([]string{"kevaso.home", "203.0.113.10", "127.0.0.1"}, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"kevaso.home", "203.0.113.10", "127.0.0.1"} {
		if _, err := sc.Leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), DNSName: host, CurrentTime: now}); err != nil {
			t.Errorf("server cert not valid for %s: %v", host, err)
		}
	}
	if _, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sc.Certificate[0]}), mustKeyPEM(t, sc)); err != nil {
		t.Fatalf("server cert unusable: %v", err)
	}
}

func mustKeyPEM(t *testing.T, c tls.Certificate) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestIdentityOfNeedsExactlyOneURI(t *testing.T) {
	c := &x509.Certificate{}
	if _, err := IdentityOf(c); err == nil || !strings.Contains(err.Error(), "0 URI") {
		t.Fatalf("no URI: %v", err)
	}
	a, _ := url.Parse("kevaso://host/a/role/worker")
	b, _ := url.Parse("kevaso://host/b/role/worker")
	c.URIs = []*url.URL{a, b}
	if _, err := IdentityOf(c); err == nil {
		t.Fatal("two identities accepted")
	}
}
