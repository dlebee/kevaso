package kvoconfig

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

func userPair(t *testing.T, ca *pki.CA, name string, at time.Time, ttl time.Duration) (cert, key []byte) {
	t.Helper()
	id := pki.Identity{Type: "user", Name: name, Role: "cluster-admin"}
	key, csr, err := pki.NewKeyAndCSR(id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = ca.SignCSR(csr, id, at, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestAnExpiredContextCertificateNamesTheRecovery(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := userPair(t, ca, "ada", time.Now().Add(-2*time.Hour), time.Hour)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := AddContext(path, "home", "https://127.0.0.1:1", ca.PEM, cert, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.Client(path, "home"); err == nil || !strings.Contains(err.Error(), "kvoadm users resign root@127.0.0.1 --name ada") {
		t.Fatalf("expired certificate: %v", err)
	}
}

func TestARenewedContextCertificateIsTheSamePerson(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := userPair(t, ca, "ada", time.Now().Add(-20*time.Hour), 24*time.Hour)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed, err := ca.SignCSR([]byte(req.CSR), pki.Identity{Type: "user", Name: "mallory", Role: "cluster-admin"}, time.Now(), 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(signed), "ca": string(ca.PEM)})
	}))
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{sc}}
	ts.StartTLS()
	defer ts.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := AddContext(path, "home", ts.URL, ca.PEM, cert, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.Contexts["home"].Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.Client(path, "home"); err == nil || !strings.Contains(err.Error(), "mallory") {
		t.Fatalf("different identity stored: %v", err)
	}
	after, err := os.ReadFile(cfg.Contexts["home"].Certificate)
	if err != nil || string(after) != string(before) {
		t.Fatal("the certificate file was replaced")
	}
}

func TestADueContextCertificateIsRenewed(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "user", Name: "ada", Role: "cluster-admin"}
	cert, key := userPair(t, ca, "ada", time.Now().Add(-20*time.Hour), 24*time.Hour)
	old, err := pki.ParseCertificatePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed, err := ca.SignCSR([]byte(req.CSR), id, time.Now(), 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"certificate": string(signed), "ca": string(ca.PEM)})
	}))
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{sc}}
	ts.StartTLS()
	defer ts.Close()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := AddContext(path, "home", ts.URL, ca.PEM, cert, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.Client(path, "home"); err != nil {
		t.Fatal(err)
	}
	got, err := pki.ParseCertificatePEM(mustRead(t, cfg.Contexts["home"].Certificate))
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.After(old.NotAfter) {
		t.Fatal("a certificate past two thirds of its life was kept")
	}
	who, err := pki.IdentityOf(got)
	if err != nil || who != id {
		t.Fatalf("identity %v %v", who, err)
	}
}

func TestACertificateInsideTenDaysWarnsWhenRenewalFails(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, key := userPair(t, ca, "ada", time.Now().Add(-20*24*time.Hour), 25*24*time.Hour)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := AddContext(path, "home", "https://127.0.0.1:1", ca.PEM, cert, key); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var warned string
	prev := warnCert
	warnCert = func(format string, args ...any) { warned = fmt.Sprintf(format, args...) }
	t.Cleanup(func() { warnCert = prev })
	if _, _, err := cfg.Client(path, "home"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warned, "kvoadm users resign root@127.0.0.1 --name ada") {
		t.Fatalf("warning %q", warned)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
