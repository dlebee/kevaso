package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

func TestChangingARegistryServerNeedsANewValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st := store.NewMemory(0)
	srv, err := apiserver.New(st, clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.Create(ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	sec := &v1.Secret{TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "pull", Namespace: "dev"},
		Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "https://ghcr.io", Username: "ada", Data: map[string][]byte{v1.PasswordKey: []byte("pw")}}}
	if err := c.Create(ctx, sec); err != nil {
		t.Fatal(err)
	}
	var got v1.Secret
	if err := c.Get(ctx, "Secret", "dev", "pull", &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Server = "evil.example"
	err = c.Update(ctx, &got)
	if code(err) != http.StatusUnprocessableEntity || !strings.Contains(err.Error(), "server") {
		t.Fatalf("server change without a value: %v", err)
	}
	if err := c.Get(ctx, "Secret", "dev", "pull", &got); err != nil {
		t.Fatal(err)
	}
	got.Spec.Server = "evil.example"
	got.Spec.Data = map[string][]byte{v1.PasswordKey: []byte("new")}
	if err := c.Update(ctx, &got); err != nil {
		t.Fatalf("server change with a new value: %v", err)
	}
}
