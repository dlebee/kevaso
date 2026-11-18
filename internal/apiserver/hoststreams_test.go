package apiserver_test

import (
	"context"
	"io"
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

// A removal recorded on one member closes that host's watch and tunnel on every member.
// Another host's watch stays open. A reconnect is the removal 401.
func TestRemovalClosesWatchesAndTunnelsOnEveryMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	tokens := &jointoken.Issuer{Store: st, Clock: clock.Real{}}
	dir, err := os.MkdirTemp("/tmp", "kvs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ts1, admin := member(t, st, ca, tokens, filepath.Join(dir, "a.sock"))
	ts2, _ := member(t, st, ca, tokens, filepath.Join(dir, "b.sock"))
	time.Sleep(200 * time.Millisecond)
	if err := admin.Create(ctx, host("hv1")); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, host("hv2")); err != nil {
		t.Fatal(err)
	}
	enroll := func(ts *httptest.Server, name string) client.Credentials {
		t.Helper()
		tok, err := tokens.Create(ctx, name, []string{"worker"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := tlsOn(t, ts, ca.PEM, nil).Enroll(ctx, tok, name, "worker")
		if err != nil {
			t.Fatal(err)
		}
		return cred
	}
	old := enroll(ts1, "hv1")
	other := enroll(ts1, "hv2")
	hv1a := tlsOn(t, ts1, ca.PEM, &old)
	hv1b := tlsOn(t, ts2, ca.PEM, &old)
	hv2 := tlsOn(t, ts2, ca.PEM, &other)
	ch1, err := hv1a.Watch(ctx, "Host", "", "0")
	if err != nil {
		t.Fatalf("watch on member 1: %v", err)
	}
	ch2, err := hv1b.Watch(ctx, "Host", "", "0")
	if err != nil {
		t.Fatalf("watch on member 2: %v", err)
	}
	chOther, err := hv2.Watch(ctx, "Host", "", "0")
	if err != nil {
		t.Fatalf("the other host's watch: %v", err)
	}
	tun1, err := hv1a.Upgrade(ctx, http.MethodGet, "/agent/connect?host=hv1", "kevaso-tunnel", nil)
	if err != nil {
		t.Fatalf("tunnel on member 1: %v", err)
	}
	defer func() { _ = tun1.Close() }()
	tun2, err := hv1b.Upgrade(ctx, http.MethodGet, "/agent/connect?host=hv1", "kevaso-tunnel", nil)
	if err != nil {
		t.Fatalf("tunnel on member 2: %v", err)
	}
	defer func() { _ = tun2.Close() }()
	if err := admin.Delete(ctx, "Host", "", "hv1"); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, ch1, "watch on member 1")
	waitClosed(t, ch2, "watch on member 2")
	waitReadEnds(t, tun1, "tunnel on member 1")
	waitReadEnds(t, tun2, "tunnel on member 2")
	select {
	case _, ok := <-chOther:
		if !ok {
			t.Fatal("the other host's watch closed")
		}
	case <-time.After(400 * time.Millisecond):
	}
	if err := hv1a.Get(ctx, "Host", "", "hv2", host("hv2")); code(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "hv1 was removed from the cluster") {
		t.Fatalf("reconnect: %v", err)
	}
	if err := hv2.Get(ctx, "Host", "", "hv2", host("hv2")); err != nil {
		t.Fatalf("the other host: %v", err)
	}
}

func member(t *testing.T, st store.Store, ca *pki.CA, tokens *jointoken.Issuer, sock string) (*httptest.Server, *client.Client) {
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
	t.Cleanup(ts.Close)
	l, err := apiserver.ListenAdminSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer(true)
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return ts, client.NewUnix(sock)
}

func tlsOn(t *testing.T, ts *httptest.Server, ca []byte, cred *client.Credentials) *client.Client {
	t.Helper()
	var cert, key []byte
	if cred != nil {
		cert, key = cred.Certificate, cred.Key
	}
	c, err := client.NewTLS(ts.URL, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitClosed(t *testing.T, ch <-chan client.Event, what string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatalf("%s stayed open", what)
		}
	}
}

func waitReadEnds(t *testing.T, rc io.Reader, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, rc)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s stayed open", what)
	}
}
