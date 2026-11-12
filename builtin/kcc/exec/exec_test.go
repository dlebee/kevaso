package exec

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/sdk/kcc"
)

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCertController(t *testing.T) {
	// The "tool": checks it got a CSR on stdin, prints a chain made beforehand.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hosts := []string{"api.example.com"}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts}, key)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{der}
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "chain.pem")
	var buf bytes.Buffer
	for _, c := range chain {
		buf.WriteString(string(pemCert(c)))
	}
	if err := os.WriteFile(pemFile, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	prog := script(t, `[ "$1" = issue ] || exit 2
grep -q 'BEGIN CERTIFICATE REQUEST' || exit 3
echo "issuing" >&2
cat `+pemFile+"\n")
	var stderr bytes.Buffer
	c := &CertController{Name: "fake", Program: prog, Stderr: &stderr}
	got, err := c.Issue(context.Background(), kcc.Request{Issuer: "x", Hosts: hosts, CSR: csr})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(chain) || !bytes.Equal(got[0], chain[0]) || !strings.Contains(stderr.String(), "issuing") {
		t.Fatalf("chain of %d, stderr %q", len(got), stderr.String())
	}
	if _, err := (&CertController{Name: "bad", Program: script(t, "echo nothing\n"), Stderr: &stderr}).Issue(context.Background(), kcc.Request{CSR: csr}); err == nil {
		t.Error("a program printing no certificate succeeded")
	}
	if _, err := (&CertController{Name: "slow", Program: script(t, "sleep 5\n"), Timeout: 100 * time.Millisecond, Stderr: &stderr}).Issue(context.Background(), kcc.Request{CSR: csr}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("slow program: %v", err)
	}
}

func TestDNSProvider(t *testing.T) {
	log := filepath.Join(t.TempDir(), "log")
	p := &DNSProvider{Program: script(t, `echo "$@" >> `+log+"\n")}
	ctx := context.Background()
	if err := p.Present(ctx, "_acme-challenge.example.com.", "abc"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp(ctx, "_acme-challenge.example.com.", "abc"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	if string(b) != "present _acme-challenge.example.com. abc\ncleanup _acme-challenge.example.com. abc\n" {
		t.Fatalf("calls: %q", b)
	}
	if err := (&DNSProvider{Program: script(t, "exit 1\n")}).Present(ctx, "x.", "y"); err == nil {
		t.Error("a failing provider succeeded")
	}
}

func TestParseRegistration(t *testing.T) {
	if n, p, err := ParseRegistration("cf=/etc/kevaso/dns/cf"); err != nil || n != "cf" || p != "/etc/kevaso/dns/cf" {
		t.Fatal(n, p, err)
	}
	for _, s := range []string{"cf", "=/x", "cf=", "cf=relative/path"} {
		if _, _, err := ParseRegistration(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDiscover(t *testing.T) {
	if m, err := Discover(filepath.Join(t.TempDir(), "missing")); err != nil || len(m) != 0 {
		t.Fatalf("missing dir: %v %v", m, err)
	}
	dir := filepath.Join(t.TempDir(), "dns-providers")
	must(t, os.Mkdir(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "cloudflare"), []byte("#!/bin/sh\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte(""), 0o644))
	m, err := Discover(dir)
	if err != nil || m["cloudflare"] != filepath.Join(dir, "cloudflare") || len(m) != 1 {
		t.Fatalf("%v %v", m, err)
	}
	must(t, os.WriteFile(filepath.Join(dir, "loose"), []byte("#!/bin/sh\n"), 0o755))
	must(t, os.Chmod(filepath.Join(dir, "loose"), 0o757))
	if _, err := Discover(dir); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("an others-writable program: %v", err)
	}
	must(t, os.Remove(filepath.Join(dir, "loose")))
	must(t, os.WriteFile(filepath.Join(dir, "notes"), []byte("x"), 0o644))
	if _, err := Discover(dir); err == nil || !strings.Contains(err.Error(), "executable") {
		t.Errorf("a non-executable file: %v", err)
	}
	must(t, os.Remove(filepath.Join(dir, "notes")))
	must(t, os.Chmod(dir, 0o777))
	if _, err := Discover(dir); err == nil {
		t.Error("a world-writable directory was trusted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
