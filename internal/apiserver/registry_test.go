package apiserver

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func TestARegistryServerOrUserChangeIsLoosening(t *testing.T) {
	old := &v1.Secret{Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "https://ghcr.io", Username: "ada"}}
	server := &v1.Secret{Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "evil.example", Username: "ada"}}
	user := &v1.Secret{Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "mallory"}}
	same := &v1.Secret{Spec: v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "ada"}}
	if !loosens(old, server) || !loosens(old, user) {
		t.Fatal("changing a registry secret's server or username was not a loosening")
	}
	if loosens(old, same) {
		t.Fatal("the same registry, written differently, was a loosening")
	}
}
