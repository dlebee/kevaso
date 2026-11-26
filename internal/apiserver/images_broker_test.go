package apiserver_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

// A pull credential is for the spec's image, or for a status ref on that same registry.
// A status ref on another registry is refused, so the namespace's default pull secret for
// that registry is not given to the host.
func TestAPullCredentialFollowsTheSpecImage(t *testing.T) {
	e := setupAuthWithVault(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(e.admin.Create(e.ctx, ns("dev")))
	must(e.admin.Create(e.ctx, host("hv2")))
	reg := func(name, server, user, pass string) {
		t.Helper()
		must(e.admin.Create(e.ctx, &v1.Secret{
			TypeMeta:   tm("Secret"),
			ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev", Labels: map[string]string{v1.LabelDefaultPull: "true"}},
			Spec:       v1.SecretSpec{Type: v1.SecretRegistry, Server: server, Username: user, Data: map[string][]byte{v1.PasswordKey: []byte(pass)}},
		}))
	}
	reg("ghcr", "https://ghcr.io", "bot", "ghcr-tok")
	reg("evil", "https://evil.example", "bot", "evil-tok")

	silo := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ghcr.io/acme/api:v1"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	must(e.admin.Create(e.ctx, silo))
	silo.Status.Host = "hv2"
	must(e.admin.UpdateStatus(e.ctx, silo))

	tok, err := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)

	var cur v1.Silo
	must(worker.Get(e.ctx, "Silo", "dev", "api", &cur))
	cur.Status.Image = &v1.SiloImage{From: "ghcr.io/acme/api:v1", Ref: "evil.example/steal:v1"}
	must(worker.UpdateStatus(e.ctx, &cur))

	ask := func(image string) client.BrokerResponse {
		t.Helper()
		var resp client.BrokerResponse
		must(worker.Get(e.ctx, "Silo", "dev", "api", &cur))
		if err := worker.Call(e.ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
			Namespace: "dev", Name: "api", UID: cur.UID, Host: "hv2",
			Request: client.BrokerRequest{Op: client.OpPullCredential, Name: image},
		}, &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := ask("evil.example/steal:v1"); r.Registry != nil || r.Error == "" {
		t.Fatalf("credential for a status ref on another registry: %+v", r.Error)
	}
	if r := ask("ghcr.io/acme/api:v1"); r.Registry == nil || r.Registry.Server != "ghcr.io" || !bytes.Equal(r.Registry.Password, []byte("ghcr-tok")) {
		t.Fatalf("credential for the spec image: error %q server %v", r.Error, registryServer(r))
	}

	must(worker.Get(e.ctx, "Silo", "dev", "api", &cur))
	cur.Status.Image = &v1.SiloImage{From: "ghcr.io/acme/api:v1", Ref: "ghcr.io/acme/api:rebuilt"}
	must(worker.UpdateStatus(e.ctx, &cur))
	if r := ask("ghcr.io/acme/api:rebuilt"); r.Registry == nil || r.Registry.Server != "ghcr.io" || !bytes.Equal(r.Registry.Password, []byte("ghcr-tok")) {
		t.Fatalf("credential for a rebuilt ref on the spec's registry: error %q server %v", r.Error, registryServer(r))
	}
}

func registryServer(r client.BrokerResponse) string {
	if r.Registry == nil {
		return ""
	}
	return r.Registry.Server
}

func setupAuthWithVault(t *testing.T) *authEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	now := time.Now()
	ca, err := pki.NewCA("test", now)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory(0)
	tokens := &jointoken.Issuer{Store: st, Clock: clock.Real{}}
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kms.OpenLocal(t.TempDir() + "/k.json")
	if err != nil {
		t.Fatal(err)
	}
	srv.SetVault(&secrets.Vault{Store: st, KMS: key, Now: time.Now})
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = srv.TLSConfig(sc)
	ts.StartTLS()
	t.Cleanup(ts.Close)

	dir, err := os.MkdirTemp("/tmp", "kva")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "admin.sock")
	l, err := apiserver.ListenAdminSocket(sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer(true)
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return &authEnv{url: ts.URL, ca: ca, tokens: tokens, admin: client.NewUnix(sock), ctx: ctx}
}
