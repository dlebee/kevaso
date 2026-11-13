package kvo

import (
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// kvo create secret NAME --type registry --server HOST --username U --from-file -: --server is the
// registry there (the API server still comes from $KVO_SERVER), the password comes from stdin only.
func TestRegistrySecretFlags(t *testing.T) {
	env := func(k string) string { return map[string]string{"KVO_SERVER": "http://127.0.0.1:7443"}[k] }
	o, err := parse([]string{"secret", "ghcr-pull", "--type", "registry", "--server", "https://ghcr.io", "--username", "bot", "--from-file", "-", "--default-pull"}, env)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KVO_SERVER", "http://127.0.0.1:7443")
	registryServer("create", &o)
	if o.secret.server != "https://ghcr.io" || o.server != "http://127.0.0.1:7443" {
		t.Fatalf("registry %q, API %q", o.secret.server, o.server)
	}
	value, err := o.secret.value(strings.NewReader("tok-1\n"))
	if err != nil || string(value) != "tok-1" {
		t.Fatalf("value %q %v", value, err)
	}
	s := &v1.Secret{}
	if err := registrySecret(s, o.secret); err != nil {
		t.Fatal(err)
	}
	if s.Spec.Server != "ghcr.io" || s.Spec.Username != "bot" || s.Labels[v1.LabelDefaultPull] != "true" {
		t.Fatalf("secret %+v %v", s.Spec, s.Labels)
	}
	for _, bad := range []secretOpts{
		{typ: v1.SecretRegistry, username: "bot"},                                    // no server
		{typ: v1.SecretRegistry, server: "ghcr.io"},                                  // no user
		{typ: v1.SecretRegistry, server: "ghcr.io", username: "bot", generate: true}, // a generated password
		{typ: v1.SecretOpaque, server: "ghcr.io"},                                    // registry flags elsewhere
	} {
		if err := registrySecret(&v1.Secret{}, bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// Without --type registry, --server is the API server, as everywhere.
	o, _ = parse([]string{"secret", "x", "--server", "http://10.0.0.1:7443"}, env)
	registryServer("create", &o)
	if o.server != "http://10.0.0.1:7443" || o.secret.server != "" {
		t.Fatalf("--server taken from the API: %q %q", o.server, o.secret.server)
	}
}

func TestMutableNote(t *testing.T) {
	for image, want := range map[string]string{
		"ghcr.io/acme/api:v12": "tag v12 is mutable",
		"nginx":                "tag latest is mutable",
		"ubuntu-24.04":         "docker.io/library/ubuntu:24.04, a tag",
		"ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64): "",
	} {
		got := MutableNote(image)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", image, got, want)
		}
	}
}
