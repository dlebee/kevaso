package apiserver_test

import (
	"context"
	"net/http/httptest"
	"sync"
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

// failSecretUpdate refuses the next update of a Secret object, and no other write.
type failSecretUpdate struct {
	store.Store
	mu  sync.Mutex
	arm bool
}

func (f *failSecretUpdate) armSecret() {
	f.mu.Lock()
	f.arm = true
	f.mu.Unlock()
}

func (f *failSecretUpdate) Update(ctx context.Context, key store.Key, data []byte, expected int64) (store.Object, error) {
	f.mu.Lock()
	if f.arm && key.Kind == "Secret" {
		f.arm = false
		f.mu.Unlock()
		return store.Object{}, store.ErrConflict
	}
	f.mu.Unlock()
	return f.Store.Update(ctx, key, data, expected)
}

// A loosening write that does not commit keeps the value the secret had. The new value is sealed
// only for a commit that stays.
func TestARefusedLooseningWriteKeepsThePreviousSecretValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mem := store.NewMemory(0)
	st := &failSecretUpdate{Store: mem}
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
	no := false
	sec := &v1.Secret{TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "tok", Namespace: "dev"},
		Spec: v1.SecretSpec{Value: []byte("old-value"), ValueReadable: &no}}
	if err := c.Create(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if got, _, err := srv.Vault().Value(ctx, sec); err != nil || string(got) != "old-value" {
		t.Fatalf("value before the refused write: %q %v", got, err)
	}
	var cur v1.Secret
	if err := c.Get(ctx, "Secret", "dev", "tok", &cur); err != nil {
		t.Fatal(err)
	}
	yes := true
	cur.Spec.ValueReadable = &yes
	cur.Spec.Value = []byte("new-value")
	st.armSecret()
	if err := c.Update(ctx, &cur); !client.IsConflict(err) {
		t.Fatalf("loosening write: %v, want a conflict", err)
	}
	if err := c.Get(ctx, "Secret", "dev", "tok", &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Readable() {
		t.Fatal("the refused write left the secret readable")
	}
	got, _, err := srv.Vault().Value(ctx, &cur)
	if err != nil || string(got) != "old-value" {
		t.Fatalf("value after the refused write: %q %v", got, err)
	}
}
