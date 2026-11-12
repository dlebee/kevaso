package certificate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/builtin/kcc/acme"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kcc"
)

func TestSealedStore(t *testing.T) {
	ctx := context.Background()
	k, err := kms.OpenLocal(filepath.Join(t.TempDir(), "kms.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(10)
	s := &SealedStore{Store: st, KMS: k}
	if _, err := s.Get(ctx, "pebble", "account-key"); !errors.Is(err, acme.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	secret := []byte("account-key-bytes-0123456789")
	for _, v := range [][]byte{secret, append(secret, '2')} { // create, then update
		if err := s.Put(ctx, "pebble", "account-key", v); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "pebble", "account-key")
		if err != nil || !bytes.Equal(got, v) {
			t.Fatalf("get = %q, %v", got, err)
		}
	}
	o, err := st.Get(ctx, stateKey("pebble", "account-key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(o.Data, secret) {
		t.Fatal("the state is in the store unsealed")
	}
	if _, err := s.Get(ctx, "other", "account-key"); !errors.Is(err, acme.ErrNotFound) {
		t.Fatal("one issuer's state is visible to another")
	}
}

func TestHTTP01Solver(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(10)
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	s := &HTTP01Solver{Store: st, Now: func() time.Time { return now }}
	if err := s.Present(ctx, "api.example.com", "tok", "tok.thumb"); err != nil {
		t.Fatal(err)
	}
	if err := s.Present(ctx, "api.example.com", "tok", "tok.thumb"); err != nil {
		t.Fatalf("presenting twice: %v", err)
	}
	o, err := st.Get(ctx, store.Key{Kind: KindChallenge, Name: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	var ch Challenge
	if err := json.Unmarshal(o.Data, &ch); err != nil || ch.KeyAuth != "tok.thumb" || ch.Host != "api.example.com" || !ch.Expires.After(now) {
		t.Fatalf("challenge %+v, %v", ch, err)
	}
	if err := s.CleanUp(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, store.Key{Kind: KindChallenge, Name: "tok"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cleaned-up challenge still there")
	}
}

func TestRegistryAndACMEConfig(t *testing.T) {
	r := BuiltinCertControllers(nil, nil, nil, time.Now, nil)
	for _, n := range []string{"acme", "internal-ca"} {
		if c, err := r.Get(n); err != nil || c.Info().Name != n {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := r.Get("certbot"); err == nil {
		t.Error("an unknown cert-controller was found")
	}
	a, _ := r.Get("acme")
	if _, err := a.Issue(context.Background(), kcc.Request{Config: json.RawMessage(`{}`)}); err == nil {
		t.Error("acme issued without a server")
	}
	if _, err := (&acme.Controller{}).Issue(context.Background(), kcc.Request{Config: json.RawMessage(`{"server":"https://acme.invalid/dir"}`)}); err == nil {
		t.Error("acme issued without a solver")
	}
}
