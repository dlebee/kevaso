package apiserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// needsYes names the approval after the secret that is stored now. A secret deleted and created
// again has a new uid, so the old approval is not this one.
func TestNeedsYesNamesTheSecretUID(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory(0)
	srv, err := New(st, clock.NewFake(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	put := func(key store.Key, obj any) {
		t.Helper()
		data, err := json.Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.Create(ctx, key, data); err != nil {
			t.Fatal(err)
		}
	}
	tm := func(kind string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: kind} }
	put(store.Key{Kind: "Namespace", Name: "dev"}, &v1.Namespace{
		TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "dev"},
	})
	put(store.Key{Kind: "Secret", Namespace: "dev", Name: "tok"}, &v1.Secret{
		TypeMeta: tm("Secret"), ObjectMeta: meta.ObjectMeta{Name: "tok", Namespace: "dev", UID: "sec-2"},
	})
	allow, resp, _ := srv.needsYes(ctx, approvals.Call{
		Namespace: "dev", Silo: "claude-1", SiloUID: "uid-1", Secret: "tok",
		Use: v1.ApprovalForSecret, Grant: "dangerous",
	})
	if allow {
		t.Fatal("a first ask was allowed")
	}
	name := approvals.Name("claude-1", "uid-1", v1.ApprovalForSecret, "tok", "sec-2")
	if resp.Pending == nil || resp.Pending.Name != name {
		t.Fatalf("pending %v, want approval %s", resp.Pending, name)
	}
	got, _, err := srv.getApproval(ctx, "dev", name)
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.SecretUID != "sec-2" {
		t.Fatalf("approval is for secret uid %q", got.Spec.SecretUID)
	}
}
