package secrets

import (
	"context"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func TestRegistryValueOpensOnlyForItsServer(t *testing.T) {
	ctx := context.Background()
	v, _ := newVault(t)
	s := secret("pull", "u1", v1.SecretRegistry)
	s.Spec.Server = "https://ghcr.io/v2/"
	s.Spec.Username = "ada"
	if _, err := v.Put(ctx, s, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	got, _, err := v.Value(ctx, s)
	if err != nil || string(got) != "pw" {
		t.Fatalf("open for the registry it was written for: %q %v", got, err)
	}
	same := secret("pull", "u1", v1.SecretRegistry)
	same.Spec.Server = "ghcr.io" // the same host, written differently
	same.Spec.Username = "ada"
	if got, _, err := v.Value(ctx, same); err != nil || string(got) != "pw" {
		t.Fatalf("the same registry, written differently: %q %v", got, err)
	}
	other := secret("pull", "u1", v1.SecretRegistry)
	other.Spec.Server = "evil.example"
	other.Spec.Username = "ada"
	if _, _, err := v.Value(ctx, other); err == nil {
		t.Fatal("a registry secret's value opened for a different server")
	}
}
