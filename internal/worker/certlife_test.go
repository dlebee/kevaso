package worker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

func clientPair(t *testing.T, ca *pki.CA, id pki.Identity, at time.Time, ttl time.Duration) (cert, key []byte) {
	t.Helper()
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

func TestJoinReenrollsAnExpiredCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	tokens := &jointoken.Issuer{Store: st, Clock: clock.Real{}}
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = srv.TLSConfig(sc)
	ts.StartTLS()
	defer ts.Close()
	dir, err := os.MkdirTemp("/tmp", "kve")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	l, err := apiserver.ListenAdminSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer(true)
	go func() { _ = hs.Serve(l) }()
	defer func() { _ = hs.Close() }()
	admin := client.NewUnix(sock)
	if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "host", Name: "hv1", Role: "worker"}
	cert, key := clientPair(t, ca, id, time.Now().Add(-2*time.Hour), time.Hour)
	data := filepath.Join(dir, "lib")
	pkiDir := filepath.Join(data, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "host.crt"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkiDir, "host.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "join-token")
	cfg := JoinConfig{HostName: "hv1", Server: ts.URL, CAFile: caFile, TokenFile: tokenFile, DataDir: data}
	_, err = Join(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), pkiDir) || !strings.Contains(err.Error(), "kvoadm host add") {
		t.Fatalf("expired, no token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pkiDir, "host.crt")); err != nil {
		t.Fatal(err)
	}
	tok, err := tokens.Create(ctx, "hv1", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Join(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(data, "pki.expired-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expired pki moved aside: %v %v", matches, err)
	}
	if err := c.Get(ctx, "Host", "", "hv1", &v1.Host{}); err != nil {
		t.Fatalf("enrolled again: %v", err)
	}
}

func TestRenewHostCertificateWhenDue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: clock.Real{}}})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = srv.TLSConfig(sc)
	ts.StartTLS()
	defer ts.Close()
	dir, err := os.MkdirTemp("/tmp", "kvr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	l, err := apiserver.ListenAdminSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer(true)
	go func() { _ = hs.Serve(l) }()
	defer func() { _ = hs.Close() }()
	admin := client.NewUnix(sock)
	if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "host", Name: "hv1", Role: "worker"}
	cert, key := clientPair(t, ca, id, time.Now().Add(-20*time.Hour), 24*time.Hour)
	data := filepath.Join(dir, "lib")
	if err := os.MkdirAll(filepath.Join(data, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(data, "pki", "host.crt")
	if err := os.WriteFile(certPath, cert, 0o644); err != nil || os.WriteFile(filepath.Join(data, "pki", "host.key"), key, 0o600) != nil {
		t.Fatal(err)
	}
	old, err := pki.ParseCertificatePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.NewTLS(ts.URL, ca.PEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := RenewHostCertificate(ctx, c, data, time.Now())
	if err != nil || !renewed {
		t.Fatalf("renew: %v %v", renewed, err)
	}
	next, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pki.ParseCertificatePEM(next)
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.After(old.NotAfter) {
		t.Fatalf("not renewed: %s", got.NotAfter)
	}
	who, err := pki.IdentityOf(got)
	if err != nil || who != id {
		t.Fatalf("identity %v %v", who, err)
	}
	if err := c.Get(ctx, "Host", "", "hv1", &v1.Host{}); err != nil {
		t.Fatalf("the renewed certificate was not presented: %v", err)
	}
}

func TestRenewRefusesADifferentHost(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mine := pki.Identity{Type: "host", Name: "hv1", Role: "worker"}
	other := pki.Identity{Type: "host", Name: "evil", Role: "worker"}
	cert, key := clientPair(t, ca, mine, time.Now().Add(-20*time.Hour), 24*time.Hour)
	var presented string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			presented = r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		}
		if r.URL.Path != "/renew" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed, err := ca.SignCSR([]byte(req.CSR), other, time.Now(), 24*time.Hour)
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
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{sc}, ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	defer ts.Close()
	dir := t.TempDir()
	data := filepath.Join(dir, "lib")
	if err := os.MkdirAll(filepath.Join(data, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(data, "pki", "host.crt")
	if err := os.WriteFile(certPath, cert, 0o644); err != nil || os.WriteFile(filepath.Join(data, "pki", "host.key"), key, 0o600) != nil {
		t.Fatal(err)
	}
	c, err := client.NewTLS(ts.URL, ca.PEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewHostCertificate(context.Background(), c, data, time.Now()); err == nil || !strings.Contains(err.Error(), "evil") {
		t.Fatalf("different identity stored: %v", err)
	}
	got, err := os.ReadFile(certPath)
	if err != nil || string(got) != string(cert) {
		t.Fatal("the certificate file was replaced")
	}
	_ = presented
}

func TestTheLiveClientPresentsTheRenewedCertificate(t *testing.T) {
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := pki.Identity{Type: "host", Name: "hv1", Role: "worker"}
	cert, key := clientPair(t, ca, id, time.Now().Add(-20*time.Hour), 24*time.Hour)
	old, err := pki.ParseCertificatePEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	var last string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			last = r.TLS.PeerCertificates[0].SerialNumber.Text(16)
		}
		if r.URL.Path != "/renew" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{sc}, ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	defer ts.Close()
	dir := t.TempDir()
	data := filepath.Join(dir, "lib")
	if err := os.MkdirAll(filepath.Join(data, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "pki", "host.crt"), cert, 0o644); err != nil ||
		os.WriteFile(filepath.Join(data, "pki", "host.key"), key, 0o600) != nil {
		t.Fatal(err)
	}
	c, err := client.NewTLS(ts.URL, ca.PEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RenewHostCertificate(context.Background(), c, data, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Raw(context.Background(), http.MethodGet, "/ping"); err != nil {
		t.Fatal(err)
	}
	if last == "" || last == old.SerialNumber.Text(16) {
		t.Fatalf("the next handshake still presented %s", old.SerialNumber.Text(16))
	}
}
