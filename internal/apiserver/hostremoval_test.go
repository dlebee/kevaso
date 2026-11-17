package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// A certificate issued before a host was deleted is refused after a restart over the same store.
// One issued by joining again is accepted. Another host's certificate is unaffected.
func TestDeletedHostCertificateIsRefusedUntilItJoinsAgain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The clock is the wall clock. SignCSR backdates NotBefore by a minute, so a certificate issued
	// in that same minute is before the removal unless enrollment clamps it. The clamp is one
	// second after the removal; TLS will not present that certificate until the second has passed.
	now := time.Now()
	ca, err := pki.NewCA("test", now)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	tokens := &jointoken.Issuer{Store: st, Clock: clock.Real{}}
	start := func() (*apiserver.Server, *httptest.Server, *client.Client) {
		t.Helper()
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
		dir, err := os.MkdirTemp("/tmp", "kva")
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
		t.Cleanup(func() {
			ts.Close()
			_ = hs.Close()
		})
		return srv, ts, client.NewUnix(sock)
	}
	tlsClient := func(ts *httptest.Server, cred *client.Credentials) *client.Client {
		t.Helper()
		var cert, key []byte
		if cred != nil {
			cert, key = cred.Certificate, cred.Key
		}
		c, err := client.NewTLS(ts.URL, ca.PEM, cert, key)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	enroll := func(ts *httptest.Server, name string) client.Credentials {
		t.Helper()
		tok, err := tokens.Create(ctx, name, []string{"worker"}, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := tlsClient(ts, nil).Enroll(ctx, tok, name, "worker")
		if err != nil {
			t.Fatalf("enroll %s: %v", name, err)
		}
		return cred
	}

	_, ts, admin := start()
	if err := admin.Create(ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, host("hv2")); err != nil {
		t.Fatal(err)
	}
	old := enroll(ts, "hv1")
	other := enroll(ts, "hv2")
	if err := admin.Delete(ctx, "Host", "", "hv1"); err != nil {
		t.Fatal(err)
	}
	if err := tlsClient(ts, &old).Get(ctx, "Host", "", "hv2", host("hv2")); code(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "hv1 was removed from the cluster") || !strings.Contains(err.Error(), "kvoadm host add") {
		t.Fatalf("old certificate: %v", err)
	}
	if err := tlsClient(ts, &other).Get(ctx, "Host", "", "hv2", host("hv2")); err != nil {
		t.Fatalf("the other host: %v", err)
	}
	if err := admin.Create(ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	fresh := enroll(ts, "hv1")
	time.Sleep(2 * time.Second)
	if err := tlsClient(ts, &fresh).Get(ctx, "Host", "", "hv1", host("hv1")); err != nil {
		t.Fatalf("certificate issued after joining again: %v", err)
	}

	// The refusal is in the store: a new server over the same store still refuses the old certificate.
	_, ts2, _ := start()
	if err := tlsClient(ts2, &old).Get(ctx, "Host", "", "hv2", host("hv2")); code(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "was removed from the cluster") {
		t.Fatalf("after restart, old certificate: %v", err)
	}
	if err := tlsClient(ts2, &fresh).Get(ctx, "Host", "", "hv1", host("hv1")); err != nil {
		t.Fatalf("after restart, the new certificate: %v", err)
	}
	if err := tlsClient(ts2, &other).Get(ctx, "Host", "", "hv2", host("hv2")); err != nil {
		t.Fatalf("after restart, the other host: %v", err)
	}
}
