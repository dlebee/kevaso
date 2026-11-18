package worker

import (
	"context"
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

func TestJoinAgainAfterRemovalMovesPKIAside(t *testing.T) {
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
	dir, err := os.MkdirTemp("/tmp", "kvj")
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
	host := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{ExternalIP: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	if err := admin.Create(ctx, host); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, ca.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "lib")
	tokenFile := filepath.Join(dir, "join-token")
	writeToken := func() {
		t.Helper()
		tok, err := tokens.Create(ctx, "hv1", []string{"worker"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tokenFile, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := JoinConfig{HostName: "hv1", Server: ts.URL, CAFile: caFile, TokenFile: tokenFile, DataDir: data}
	writeToken()
	if _, err := Join(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(filepath.Join(data, "pki", "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	// A working certificate is kept, including when a token file is also present.
	writeToken()
	if _, err := Join(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(filepath.Join(data, "pki", "host.crt"))
	if err != nil || string(again) != string(cert) {
		t.Fatalf("a working certificate was replaced: %v", err)
	}
	// A server that cannot be reached is not a removal: the certificate stays.
	down := cfg
	down.DataDir = filepath.Join(dir, "down")
	if err := os.MkdirAll(filepath.Join(down.DataDir, "pki"), 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(data, "pki", "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(down.DataDir, "pki", "host.crt"), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(down.DataDir, "pki", "host.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	down.Server = "https://127.0.0.1:1"
	if _, err := Join(ctx, down); err != nil {
		t.Fatalf("a connection error moved the certificate aside: %v", err)
	}
	if _, err := os.Stat(filepath.Join(down.DataDir, "pki", "host.crt")); err != nil {
		t.Fatal(err)
	}

	if err := admin.Delete(ctx, "Host", "", "hv1"); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(tokenFile)
	_, err = Join(ctx, cfg)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(data, "pki")) || !strings.Contains(err.Error(), "kvoadm host add") {
		t.Fatalf("removed, no token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "pki", "host.crt")); err != nil {
		t.Fatalf("the certificate was moved with no token: %v", err)
	}
	if err := admin.Create(ctx, host); err != nil {
		t.Fatal(err)
	}
	writeToken()
	c, err := Join(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(data, "pki.removed-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("pki moved aside: %v %v", matches, err)
	}
	if _, err := os.Stat(filepath.Join(matches[0], "host.key")); err != nil {
		t.Fatalf("the old key was deleted: %v", err)
	}
	time.Sleep(2 * time.Second)
	if err := c.Get(ctx, "Host", "", "hv1", &v1.Host{}); err != nil {
		t.Fatalf("joined again: %v", err)
	}
}

func TestHeartbeatRemovalIsFinal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusUnauthorized, Reason: "Unauthorized", Message: "host hv1 was removed from the cluster; join it again with kvoadm host add"})
	}))
	defer srv.Close()
	fired := make(chan struct{}, 1)
	contact := &Contact{}
	contact.OnRemoved(func() { fired <- struct{}{} })
	done := make(chan struct{})
	go func() {
		Heartbeat(context.Background(), client.New(srv.URL), "hv1", time.Hour, clock.Real{}, func(string, ...any) {}, contact)
		close(done)
	}()
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("the removal was not reported")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat kept retrying a removal")
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(client.Error{Code: http.StatusInternalServerError, Reason: "Internal", Message: "unavailable"})
	}))
	defer other.Close()
	n := 0
	ctx, cancel := context.WithCancel(context.Background())
	gone := make(chan struct{})
	go func() {
		Heartbeat(ctx, client.New(other.URL), "hv1", time.Hour, clock.Real{}, func(string, ...any) { n++ }, nil)
		close(gone)
	}()
	time.Sleep(100 * time.Millisecond)
	select {
	case <-gone:
		t.Fatal("an ordinary error ended the heartbeat")
	default:
	}
	cancel()
	select {
	case <-gone:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat did not stop when asked")
	}
	if n == 0 {
		t.Fatal("the ordinary error was not logged")
	}
}
