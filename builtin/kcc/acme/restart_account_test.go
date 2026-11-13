package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memStore) Get(_ context.Context, issuer, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[issuer+"/"+key]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (s *memStore) Put(_ context.Context, issuer, key string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[issuer+"/"+key] = v
	return nil
}

// acmeAccounts is the account half of an ACME server: its first newAccount fails (the server
// down, or kevasod killed, or leadership lost, mid-call).
type acmeAccounts struct {
	mu         sync.Mutex
	calls      int
	registered bool
}

func (a *acmeAccounts) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", "n"+strings.Repeat("x", 16))
	base := "http://" + r.Host
	switch r.URL.Path {
	case "/dir":
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order"})
	case "/nonce":
		w.WriteHeader(http.StatusOK)
	case "/acct":
		var jws struct{ Payload string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &jws)
		p, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
		var req struct{ OnlyReturnExisting bool }
		_ = json.Unmarshal(p, &req)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.calls++
		problem := func(code int, typ string) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:` + typ + `"}`))
		}
		switch {
		case a.calls == 1:
			problem(http.StatusForbidden, "unauthorized")
		case !a.registered && req.OnlyReturnExisting:
			problem(http.StatusBadRequest, "accountDoesNotExist")
		default:
			code := http.StatusOK
			if !a.registered {
				code = http.StatusCreated
			}
			a.registered = true
			w.Header().Set("Location", base+"/acct/1")
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"status":"valid"}`))
		}
	default:
		http.NotFound(w, r)
	}
}

// The account key is stored before the account is registered. When that registration failed,
// every later client found the key, took it as registered, and sent its orders without an account:
// the issuer never issued again, and the certificates it had expired.
func TestAnAccountWhoseRegistrationFailedIsRegisteredNextTime(t *testing.T) {
	srv := &acmeAccounts{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := &Controller{Store: &memStore{m: map[string][]byte{}}, HTTP: ts.Client()}
	cfg := Config{Server: ts.URL + "/dir"}
	ctx := context.Background()
	if _, err := c.client(ctx, "le", cfg); err == nil {
		t.Fatal("the first registration should have failed")
	}
	cl, err := c.client(ctx, "le", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	registered := srv.registered
	srv.mu.Unlock()
	if !registered {
		t.Fatal("the key is stored, its account was never registered: every order goes without one")
	}
	if cl.KID == "" {
		t.Fatal("the client doesn't know its account")
	}
}
