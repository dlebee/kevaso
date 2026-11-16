package apiserver_test

import (
	"context"
	"errors"
	"net/http/httptest"
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

// Removing the last finalizer deletes the Secret and its sealed value. A value left behind
// would still be in the store after the object is gone.
func TestASecretDeletedByItsLastFinalizerDropsTheSealedValue(t *testing.T) {
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
	if err := c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"}}); err != nil {
		t.Fatal(err)
	}
	sec := &v1.Secret{TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "tok", Namespace: "dev", Finalizers: []string{"kevaso.com/hold"}},
		Spec: v1.SecretSpec{Value: []byte("s3cret")}}
	if err := c.Create(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "Secret", "dev", "tok"); err != nil {
		t.Fatal(err)
	}
	valueKey := store.Key{Kind: secrets.KindValue, Namespace: "dev", Name: "tok"}
	if _, err := st.Get(ctx, valueKey); err != nil {
		t.Fatalf("value while a finalizer still holds the secret: %v", err)
	}
	var got v1.Secret
	if err := c.Get(ctx, "Secret", "dev", "tok", &got); err != nil {
		t.Fatal(err)
	}
	got.Finalizers = nil
	if err := c.Update(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, "Secret", "dev", "tok", &got); !client.IsNotFound(err) {
		t.Fatalf("secret after its last finalizer: %v", err)
	}
	if _, err := st.Get(ctx, valueKey); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sealed value after the secret was deleted: %v", err)
	}
}
