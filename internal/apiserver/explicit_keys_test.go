package apiserver_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Keys are always explicit (hack/design/secret-keys.md): writes name every key, fixed-shape secrets
// hold their own key names, /value names a key or "*", grants name a key or "*", and the broker
// answers exactly the key asked for.

func tmeta(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func TestExplicitKeysWrites(t *testing.T) {
	e := setupAuthWithVault(t)
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	sec := func(name string, spec v1.SecretSpec) *v1.Secret {
		return &v1.Secret{TypeMeta: tmeta("Secret"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}, Spec: spec}
	}
	refused := func(what string, s *v1.Secret, want string) {
		t.Helper()
		err := e.admin.Create(e.ctx, s)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v; want a refusal saying %q", what, err, want)
		}
	}
	refused("a signing key under another key", sec("k1", v1.SecretSpec{Type: v1.SecretEd25519, Data: map[string][]byte{"value": make([]byte, 32)}}),
		`a ed25519 secret holds one key, "private-key"`)
	refused("a registry secret under another key", sec("r1", v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "bot", Data: map[string][]byte{"token": []byte("x")}}),
		`a registry secret holds one key, "password"`)
	refused("a registry secret with an extra key", sec("r2", v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "bot",
		Data: map[string][]byte{"password": []byte("x"), "token": []byte("y")}}), `holds one key, "password"`)
	refused("generating a signing key under another key", sec("k2", v1.SecretSpec{Type: v1.SecretEd25519, Generate: "token"}),
		`spec.generate: a ed25519 secret's key is "private-key" (generate: private-key)`)
	refused("generate naming no key", sec("g1", v1.SecretSpec{Generate: "a/b"}), `spec.generate names the key to make: "a/b"`)
	// A Secret with no keys yet holds none: nothing is made up for it.
	empty := sec("e1", v1.SecretSpec{})
	if err := e.admin.Create(e.ctx, empty); err != nil || len(empty.Status.Keys) != 0 || empty.Status.Version != 0 {
		t.Fatalf("a secret written with no key: %v, keys %v, version %d", err, empty.Status.Keys, empty.Status.Version)
	}

	// What works: generate names its key; a signing key's is private-key; a registry secret's is password.
	tok := sec("tok", v1.SecretSpec{Generate: "token"})
	if err := e.admin.Create(e.ctx, tok); err != nil || !slices.Equal(tok.Status.Keys, []string{"token"}) {
		t.Fatalf("generate: token: %v %v", err, tok.Status.Keys)
	}
	key := sec("signer", v1.SecretSpec{Type: v1.SecretEd25519, Generate: v1.PrivateKeyKey})
	if err := e.admin.Create(e.ctx, key); err != nil || !slices.Equal(key.Status.Keys, []string{v1.PrivateKeyKey}) || key.Status.PublicKey == "" {
		t.Fatalf("generate: private-key: %v %v %q", err, key.Status.Keys, key.Status.PublicKey)
	}
	pull := sec("pull", v1.SecretSpec{Type: v1.SecretRegistry, Server: "ghcr.io", Username: "bot", Data: map[string][]byte{v1.PasswordKey: []byte("pw")}})
	if err := e.admin.Create(e.ctx, pull); err != nil || !slices.Equal(pull.Status.Keys, []string{v1.PasswordKey}) {
		t.Fatalf("registry: %v %v", err, pull.Status.Keys)
	}
}

func TestExplicitKeysValueRead(t *testing.T) {
	e := setupAuthWithVault(t)
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.Secret{TypeMeta: tmeta("Secret"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SecretSpec{Data: map[string][]byte{"username": []byte("app"), "password": []byte("s3cret")}}}); err != nil {
		t.Fatal(err)
	}
	p := "/apis/kevaso/v1/namespaces/dev/secrets/db/value"
	var v client.SecretValue
	if err := e.admin.Call(e.ctx, http.MethodGet, p, nil, &v); err == nil || !strings.Contains(err.Error(), "name a key (?key=KEY), or every key (?key=*)") {
		t.Fatalf("no key named: %v %+v; want a 400 showing both forms", err, v)
	}
	v = client.SecretValue{}
	if err := e.admin.Call(e.ctx, http.MethodGet, p+"?key=*", nil, &v); err != nil || len(v.Data) != 2 || string(v.Data["password"]) != "s3cret" || v.Value != nil {
		t.Fatalf("?key=*: %v %+v", err, v)
	}
	v = client.SecretValue{}
	if err := e.admin.Call(e.ctx, http.MethodGet, p+"?key=username", nil, &v); err != nil || string(v.Value) != "app" || v.Data != nil {
		t.Fatalf("?key=username: %v %+v", err, v)
	}
	if err := e.admin.Call(e.ctx, http.MethodGet, p+"?key=value", nil, &v); err == nil || !strings.Contains(err.Error(), `has no key "value"`) {
		t.Fatalf("?key=value (no fallback): %v", err)
	}

	// A ClusterSecret's read is the same.
	if err := e.admin.Create(e.ctx, &v1.ClusterSecret{TypeMeta: tmeta("ClusterSecret"), ObjectMeta: meta.ObjectMeta{Name: "bucket"},
		Spec: v1.ClusterSecretSpec{Data: map[string][]byte{"access-key": []byte("ak")}}}); err != nil {
		t.Fatal(err)
	}
	cp := "/apis/kevaso/v1/clustersecrets/bucket/value"
	if err := e.admin.Call(e.ctx, http.MethodGet, cp, nil, &v); err == nil || !strings.Contains(err.Error(), "name a key") {
		t.Fatalf("clustersecret, no key named: %v", err)
	}
	v = client.SecretValue{}
	if err := e.admin.Call(e.ctx, http.MethodGet, cp+"?key=*", nil, &v); err != nil || string(v.Data["access-key"]) != "ak" {
		t.Fatalf("clustersecret ?key=*: %v %+v", err, v)
	}
}

func TestExplicitKeysGrantAdmission(t *testing.T) {
	e := setupAuthWithVault(t)
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.Secret{TypeMeta: tmeta("Secret"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SecretSpec{Data: map[string][]byte{"username": []byte("app"), "password": []byte("s3cret")}}}); err != nil {
		t.Fatal(err)
	}
	grant := func(name string, gs ...v1.GrantSecret) error {
		return e.admin.Create(e.ctx, &v1.Grant{TypeMeta: tmeta("Grant"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"}, Spec: v1.GrantSpec{Secrets: gs}})
	}
	to := &v1.InjectTarget{Host: "api.example.com"}
	for _, c := range []struct {
		gs   v1.GrantSecret
		want string
	}{
		{v1.GrantSecret{Name: "db"}, `secret db: key is required: name one key (key: KEY) or every key (key: "*")`},
		{v1.GrantSecret{Name: "db", Deliver: v1.DeliverEnv}, `or every key (key: "*")`},
		{v1.GrantSecret{Name: "db", Deliver: v1.DeliverInject, To: to}, "name the one key to inject (key: KEY)"},
		{v1.GrantSecret{Name: "db", Key: v1.AllKeys, Deliver: v1.DeliverInject, To: to}, `inject adds one key: name it (key: KEY), not "*"`},
		{v1.GrantSecret{Name: "db", Key: "value"}, `secret db has no key "value" (its keys: password, username)`},
		{v1.GrantSecret{Name: "db", Key: "a b"}, `key "a b"`},
	} {
		if err := grant("bad", c.gs); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v; want a refusal saying %q", c.gs, err, c.want)
		}
	}
	for i, gs := range []v1.GrantSecret{
		{Name: "db", Key: "password"},
		{Name: "db", Key: v1.AllKeys},
		{Name: "db", Key: v1.AllKeys, Deliver: v1.DeliverFile},
		{Name: "db", Key: v1.AllKeys, Deliver: v1.DeliverEnv},
		{Name: "db", Key: "password", Deliver: v1.DeliverInject, To: to},
	} {
		if err := grant("ok-"+string(rune('a'+i)), gs); err != nil {
			t.Errorf("%+v: %v", gs, err)
		}
	}
}

func TestExplicitKeysBroker(t *testing.T) {
	e := setupAuthWithVault(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(e.admin.Create(e.ctx, ns("dev")))
	must(e.admin.Create(e.ctx, host("hv2")))
	must(e.admin.Create(e.ctx, &v1.Secret{TypeMeta: tmeta("Secret"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SecretSpec{Data: map[string][]byte{"username": []byte("app"), "password": []byte("s3cret")}}}))
	must(e.admin.Create(e.ctx, &v1.Grant{TypeMeta: tmeta("Grant"), ObjectMeta: meta.ObjectMeta{Name: "one", Namespace: "dev"},
		Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: "password"}}}}))
	must(e.admin.Create(e.ctx, &v1.Grant{TypeMeta: tmeta("Grant"), ObjectMeta: meta.ObjectMeta{Name: "all", Namespace: "dev"},
		Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "db", Key: v1.AllKeys}}}}))
	silos := map[string]*v1.Silo{}
	for name, grant := range map[string]string{"api": "one", "job": "all"} {
		s := &v1.Silo{TypeMeta: tmeta("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ghcr.io/acme/api:v1"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}, Grants: []string{grant}}}
		must(e.admin.Create(e.ctx, s))
		s.Status.Host = "hv2"
		must(e.admin.UpdateStatus(e.ctx, s))
		silos[name] = s
	}
	tok, err := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	must(err)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	must(err)
	worker := e.tlsClient(t, &cred)
	ask := func(silo, key string) client.BrokerResponse {
		t.Helper()
		var resp client.BrokerResponse
		s := silos[silo]
		must(worker.Call(e.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
			Namespace: "dev", Name: silo, UID: s.UID, Host: "hv2",
			Request: client.BrokerRequest{Op: client.OpGetSecret, Name: "db", Key: key},
		}, &resp))
		return resp
	}
	refusedLikeMissing := func(what string, r client.BrokerResponse) {
		t.Helper()
		if r.Error == "" || r.Code != client.CodeNotFound || r.Value != nil || r.Data != nil {
			t.Fatalf("%s: %+v; want a not-found refusal and no value", what, r)
		}
	}

	// A grant with one key: that key by name, and "*" is just that key.
	if r := ask("api", "password"); r.Error != "" || string(r.Value) != "s3cret" || r.Data != nil {
		t.Fatalf("one key by name: %+v", r)
	}
	if r := ask("api", v1.AllKeys); r.Error != "" || len(r.Data) != 1 || string(r.Data["password"]) != "s3cret" || r.Value != nil {
		t.Fatalf(`one-key grant, "*": %+v`, r)
	}
	refusedLikeMissing("one-key grant, another key", ask("api", "username"))
	refusedLikeMissing("no key named", ask("api", ""))
	refusedLikeMissing("no key value to fall back to", ask("api", "value"))

	// A grant with "*": any key by name, and every key with "*". No key is still refused.
	if r := ask("job", "username"); r.Error != "" || string(r.Value) != "app" {
		t.Fatalf(`"*" grant, one key: %+v`, r)
	}
	if r := ask("job", v1.AllKeys); r.Error != "" || len(r.Data) != 2 || string(r.Data["username"]) != "app" || r.Value != nil {
		t.Fatalf(`"*" grant, "*": %+v`, r)
	}
	refusedLikeMissing(`"*" grant, no key named`, ask("job", ""))
	refusedLikeMissing(`"*" grant, a key it doesn't have`, ask("job", "value"))
}
