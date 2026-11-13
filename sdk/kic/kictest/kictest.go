// Package kictest helps test ingress drivers: a sample State touching every feature, golden files,
// and the checks every driver must pass.
package kictest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/sdk/kic"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Placeholder PEM: drivers only copy it.
const (
	Chain = "-----BEGIN CERTIFICATE-----\nMIIBc2FtcGxl\n-----END CERTIFICATE-----\n"
	Key   = "-----BEGIN EC PRIVATE KEY-----\nMHcCc2FtcGxl\n-----END EC PRIVATE KEY-----\n"
)

// Sample is a State with TLS and plain hosts, a host whose certificate isn't issued yet, path
// prefixes, a pending ACME challenge, and annotations (the driver's own, given).
func Sample(annotations map[string]string) kic.State {
	return kic.State{
		Class: "public",
		Routes: []kic.Route{
			{Ingress: "payments/api", Host: "api.example.com", Path: "/ws", Backend: kic.Backend{Address: "10.64.0.5", Port: 9000}, TLS: true, Annotations: annotations},
			{Ingress: "payments/api", Host: "api.example.com", Path: "/", Backend: kic.Backend{Address: "10.64.0.4", Port: 8080}, TLS: true, Annotations: annotations},
			{Ingress: "shop/pending", Host: "pending.example.com", Path: "/", Backend: kic.Backend{Address: "10.64.0.7", Port: 80}, TLS: true},
			{Ingress: "shop/plain", Host: "plain.example.com", Path: "/", Backend: kic.Backend{Address: "10.64.0.6", Port: 3000}},
		},
		Certificates: []kic.Certificate{{Name: "payments/api-tls", Ingress: "payments/api", Hosts: []string{"api.example.com"}, Chain: []byte(Chain), Key: []byte(Key)}},
		Challenges:   []kic.Challenge{{Token: "tok-123_abc", KeyAuthorization: "tok-123_abc.thumbprint-XYZ"}},
	}
}

// Golden compares got with testdata/NAME (go test -update rewrites it).
func Golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test -update writes it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what was rendered (go test -update rewrites it); got:\n%s", p, got)
	}
}

// Conformance checks what every driver must do: render the same bytes twice, keep keys in files
// marked secret (or in an admin-API call), refuse unknown and bad knobs, and refuse a State that
// would paste configuration in.
func Conformance(t *testing.T, d kic.Driver, goodAnnotations map[string]string) {
	t.Helper()
	s := Sample(goodAnnotations)
	if err := kic.Validate(d, s); err != nil {
		t.Fatalf("the sample's annotations: %v", err)
	}
	a, err := d.Render(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := d.Render(Sample(goodAnnotations))
	if a.Hash() != b.Hash() {
		t.Error("the same State rendered differently")
	}
	for _, f := range a.Files {
		if bytes.Contains(f.Data, []byte(Key)) && (!f.Secret || f.Mode.Perm()&0o077 != 0) {
			t.Errorf("%s holds a key but isn't secret and 0600: %v", f.Path, f.Mode)
		}
	}
	if bytes.Contains(a.Config.Data, []byte("PRIVATE KEY")) {
		t.Error("a key in the main config file")
	}
	if a.Config.Path == "" && a.Reload.Call == nil {
		t.Error("neither a config file nor an admin-API call")
	}
	if a.Config.Path != "" && len(a.Check) == 0 {
		t.Error("a config file with no check")
	}
	name := d.Info().Name
	refused := []map[string]string{{"no-such-knob": "1"}}
	for _, k := range d.Info().Annotations {
		if k.Valid != nil {
			refused = append(refused, map[string]string{k.Name: "1; evil"})
		}
	}
	for _, ann := range refused {
		bad := Sample(ann)
		if err := kic.Validate(d, bad); err == nil {
			t.Errorf("annotations %v (%s/…) accepted", ann, name)
		}
	}
	if err := kic.Validate(d, kic.State{Options: map[string]string{"no-such-option": "x"}}); err == nil {
		t.Error("an unknown option accepted")
	}
	for _, evil := range []kic.Route{
		{Ingress: "x/y", Host: "a.example.com; evil", Path: "/", Backend: kic.Backend{Address: "10.0.0.1", Port: 80}},
		{Ingress: "x/y", Host: "a.example.com", Path: "/ { evil", Backend: kic.Backend{Address: "10.0.0.1", Port: 80}},
		{Ingress: "x/y", Host: "a.example.com", Path: "/", Backend: kic.Backend{Address: "10.0.0.1;", Port: 80}},
		{Ingress: "x/y\nevil;", Host: "a.example.com", Path: "/", Backend: kic.Backend{Address: "10.0.0.1", Port: 80}},
	} {
		if _, err := d.Render(kic.State{Routes: []kic.Route{evil}}); err == nil {
			t.Errorf("rendered %+v", evil)
		}
	}
	if _, err := d.Render(kic.State{Class: "c\nevil;"}); err == nil {
		t.Error("rendered a class name with a newline in it")
	}
	if _, err := d.Render(kic.State{Challenges: []kic.Challenge{{Token: "t\"; evil", KeyAuthorization: "k"}}}); err == nil {
		t.Error("rendered a challenge with a quote in it")
	}
}

// Real is Sample with a real certificate and key (for running a proxy's own check on the output).
func Real(t *testing.T, annotations map[string]string) kic.State {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.example.com"}, DNSNames: []string{"api.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	s := Sample(annotations)
	s.Certificates[0].Chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	s.Certificates[0].Key = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return s
}

// Materialize writes a plan's files under dir, every absolute path in the config moved there too
// (so the proxy's own check can run on it without root), and returns the config's path. moves are
// extra paths to move (logs, pid files).
func Materialize(t *testing.T, p kic.Plan, dir string, moves ...string) string {
	t.Helper()
	cfg := string(p.Config.Data)
	for _, m := range append([]string{p.Dir}, moves...) {
		to := filepath.Join(dir, strings.ReplaceAll(strings.Trim(m, "/"), "/", "_"))
		cfg = strings.ReplaceAll(cfg, m, to)
		if filepath.Ext(m) == "" { // a folder (logs): the proxy opens files in it, so it has to exist
			if err := os.MkdirAll(to, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, f := range p.Files {
		rel := strings.ReplaceAll(strings.Trim(p.Dir, "/"), "/", "_")
		target := filepath.Join(dir, rel, filepath.Base(f.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, filepath.Base(p.Config.Path))
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
