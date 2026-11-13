package operator

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
)

// A controller uses its installed token, renews it (with itself) at half its life, keeps the new
// one in its state directory, and says what to do once it's expired.
func TestTokensRenew(t *testing.T) {
	var renewals atomic.Int32
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/kevaso/v1/namespaces/kevaso-system/serviceaccounts/plugin-sessions/token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		n := renewals.Add(1)
		if want := map[int32]string{1: "Bearer first"}[n]; want != "" && r.Header.Get("Authorization") != want {
			t.Errorf("renewal %d with %q", n, r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(client.TokenResponse{Token: "second", Expires: now.Add(90 * time.Minute)})
	}))
	defer srv.Close()
	dir, state := t.TempDir(), t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	tok, _ := json.Marshal(Token{Token: "first", Expires: now.Add(time.Hour)})
	for f, b := range map[string][]byte{"server": []byte(srv.URL + "\n"), "ca.pem": ca, "token.json": tok,
		"plugin.json": []byte(`{"name": "sessions", "version": "0.1.0", "serviceAccount": "kevaso-system/plugin-sessions"}`)} {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	creds, err := Load(dir, state)
	if err != nil {
		t.Fatal(err)
	}
	clock := now
	creds.Now = func() time.Time { return clock }
	c, err := creds.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	get := func() string {
		s, err := c.Token(context.Background())
		if err != nil {
			return "error: " + err.Error()
		}
		return s
	}
	if got := get(); got != "first" || renewals.Load() != 0 {
		t.Fatalf("fresh: %q, %d renewals", got, renewals.Load())
	}
	clock = now.Add(31 * time.Minute) // past half its life
	if got := get(); got != "second" || renewals.Load() != 1 {
		t.Fatalf("at half life: %q, %d renewals", got, renewals.Load())
	}
	if b, _ := os.ReadFile(filepath.Join(state, "token.json")); !strings.Contains(string(b), "second") {
		t.Errorf("state: %s", b)
	}
	// A restart picks the later of the two.
	again, _ := Load(dir, state)
	again.Now = creds.Now
	c2, err := again.Client(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := c2.Token(context.Background()); s != "second" {
		t.Errorf("after a restart: %q", s)
	}
	clock = now.Add(3 * time.Hour)
	if got := get(); !strings.Contains(got, "kvoadm plugin install again") {
		t.Errorf("expired: %q", got)
	}
}
