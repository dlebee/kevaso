package apiserver_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

type authEnv struct {
	url    string
	ca     *pki.CA
	tokens *jointoken.Issuer
	admin  *client.Client // over the admin socket
	ctx    context.Context
}

func setupAuth(t *testing.T) *authEnv {
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
	sc, err := ca.ServerCert([]string{"127.0.0.1"}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = srv.TLSConfig(sc)
	ts.StartTLS()
	t.Cleanup(ts.Close)

	// The admin socket (short path: unix socket paths are limited to ~104 bytes on macOS).
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
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode %v, want 0600", fi.Mode().Perm())
	}
	return &authEnv{url: ts.URL, ca: ca, tokens: tokens, admin: client.NewUnix(sock), ctx: ctx}
}

func (e *authEnv) tlsClient(t *testing.T, cred *client.Credentials) *client.Client {
	t.Helper()
	var cert, key []byte
	if cred != nil {
		cert, key = cred.Certificate, cred.Key
	}
	c, err := client.NewTLS(e.url, e.ca.PEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ns(name string) *v1.Namespace {
	return &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: name}}
}

func host(name string) *v1.Host {
	return &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.HostSpec{Address: "203.0.113.10", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
}

func code(err error) int {
	var e *client.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func TestNoCertificateIsUnauthorized(t *testing.T) {
	e := setupAuth(t)
	anon := e.tlsClient(t, nil)
	if _, err := anon.List(e.ctx, "Namespace", ""); code(err) != http.StatusUnauthorized {
		t.Fatalf("anonymous list: want 401, got %v", err)
	}
}

func TestAdminSocketMintsUserCertificates(t *testing.T) {
	e := setupAuth(t)
	// Over the socket: full access, and it can mint a cluster-admin certificate for kvo.
	if err := e.admin.Create(e.ctx, ns("dev")); err != nil {
		t.Fatalf("admin socket create: %v", err)
	}
	cred, err := e.admin.IssueUserCert(e.ctx, "david")
	if err != nil {
		t.Fatal(err)
	}
	david := e.tlsClient(t, &cred)
	if err := david.Create(e.ctx, ns("prod")); err != nil {
		t.Fatalf("cluster-admin over TLS: %v", err)
	}
	// Over TLS, even a cluster-admin can't mint certificates: only the socket can.
	if _, err := david.IssueUserCert(e.ctx, "mallory"); code(err) != http.StatusForbidden {
		t.Fatalf("issuing over TLS: want 403, got %v", err)
	}
}

func TestEnrollmentWithJoinToken(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, host("hv2"))
	_ = e.admin.Create(e.ctx, host("hv3"))
	tok, err := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	anon := e.tlsClient(t, nil)
	if _, err := anon.Enroll(e.ctx, tok, "hv2", "control-plane"); code(err) != http.StatusForbidden {
		t.Fatalf("asking for a role the token doesn't allow: want 403, got %v", err)
	}
	cred, err := anon.Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := anon.Enroll(e.ctx, tok, "hv2", "worker"); code(err) != http.StatusUnauthorized {
		t.Fatalf("reusing the token: want 401, got %v", err)
	}

	worker := e.tlsClient(t, &cred)
	// A worker reads everything...
	if _, err := worker.List(e.ctx, "Host", ""); err != nil {
		t.Fatalf("worker list: %v", err)
	}
	// ...writes its own Host's status...
	var h v1.Host
	_ = worker.Get(e.ctx, "Host", "", "hv2", &h)
	meta.SetCondition(&h.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue}, time.Now())
	if err := worker.UpdateStatus(e.ctx, &h); err != nil {
		t.Fatalf("worker updating its own status: %v", err)
	}
	// ...and nothing else: not another host's status, not its own spec, no creates.
	var other v1.Host
	_ = worker.Get(e.ctx, "Host", "", "hv3", &other)
	if err := worker.UpdateStatus(e.ctx, &other); code(err) != http.StatusForbidden {
		t.Fatalf("worker writing another host's status: want 403, got %v", err)
	}
	h.Spec.Address = "198.51.100.1"
	if err := worker.Update(e.ctx, &h); code(err) != http.StatusForbidden {
		t.Fatalf("worker writing its own spec: want 403, got %v", err)
	}
	if err := worker.Create(e.ctx, ns("x")); code(err) != http.StatusForbidden {
		t.Fatalf("worker creating: want 403, got %v", err)
	}
}

func TestWorkerWritesOnlyItsOwnSilosStatus(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	_ = e.admin.Create(e.ctx, host("hv2"))
	mk := func(name, onHost string) {
		s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
		_ = e.admin.Create(e.ctx, s)
		s.Status.Host = onHost
		if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	mk("mine", "hv2")
	mk("theirs", "hv3")
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)

	var s v1.Silo
	_ = worker.Get(e.ctx, "Silo", "dev", "mine", &s)
	s.Status.Phase = "Running"
	if err := worker.UpdateStatus(e.ctx, &s); err != nil {
		t.Fatalf("worker writing its own silo's status: %v", err)
	}
	_ = worker.Get(e.ctx, "Silo", "dev", "mine", &s)
	s.Status.Host = "hv9" // moving it elsewhere
	if err := worker.UpdateStatus(e.ctx, &s); code(err) != http.StatusForbidden {
		t.Fatalf("worker moving a silo: want 403, got %v", err)
	}
	var other v1.Silo
	_ = worker.Get(e.ctx, "Silo", "dev", "theirs", &other)
	other.Status.Phase = "Running"
	if err := worker.UpdateStatus(e.ctx, &other); code(err) != http.StatusForbidden {
		t.Fatalf("worker writing another host's silo: want 403, got %v", err)
	}
	if err := worker.Update(e.ctx, &s); code(err) != http.StatusForbidden {
		t.Fatalf("worker writing a silo's spec: want 403, got %v", err)
	}
}

func TestCertificateFromAnotherCAIsRejected(t *testing.T) {
	e := setupAuth(t)
	rogue, _ := pki.NewCA("rogue", time.Now())
	key, csr, _ := pki.NewKeyAndCSR(pki.Identity{Type: "user", Name: "admin", Role: "cluster-admin"})
	cert, _ := rogue.SignCSR(csr, pki.Identity{Type: "user", Name: "admin", Role: "cluster-admin"}, time.Now(), time.Hour)
	c, err := client.NewTLS(e.url, e.ca.PEM, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(e.ctx, "Namespace", ""); err == nil {
		t.Fatal("a certificate from another CA was accepted")
	}
}

func TestClientPinsTheClusterCA(t *testing.T) {
	e := setupAuth(t)
	other, _ := pki.NewCA("other", time.Now())
	c, err := client.NewTLS(e.url, other.PEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.List(e.ctx, "Namespace", ""); err == nil || code(err) != 0 {
		t.Fatalf("talking to a server not signed by the pinned CA must fail at TLS, got %v", err)
	}
}

// The agent tunnel over real TLS: a worker connects as itself only, may not exec, and an admin's
// exec reaches the silo through it.
func TestTunnelAndExecAuthorization(t *testing.T) {
	e := setupAuth(t)
	_ = e.admin.Create(e.ctx, ns("dev"))
	_ = e.admin.Create(e.ctx, host("hv2"))
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
	if err := e.admin.Create(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv2"
	if err := e.admin.UpdateStatus(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	tok, _ := e.tokens.Create(e.ctx, "hv2", []string{"worker"}, time.Hour)
	cred, err := e.tlsClient(t, nil).Enroll(e.ctx, tok, "hv2", "worker")
	if err != nil {
		t.Fatal(err)
	}
	worker := e.tlsClient(t, &cred)

	if _, err := worker.Upgrade(e.ctx, http.MethodGet, "/agent/connect?host=hv3", "kevaso-tunnel", nil); code(err) != http.StatusForbidden {
		t.Fatalf("worker connecting as another host: want 403, got %v", err)
	}
	if _, err := worker.Exec(e.ctx, "dev", "web", []string{"true"}, nil, nil, nil); code(err) != http.StatusForbidden {
		t.Fatalf("worker exec: want 403, got %v", err)
	}
	if _, err := e.tlsClient(t, nil).Upgrade(e.ctx, http.MethodGet, "/agent/connect?host=hv2", "kevaso-tunnel", nil); code(err) != http.StatusUnauthorized {
		t.Fatalf("no certificate: want 401, got %v", err)
	}

	rt := fake.New()
	rt.Handler = func(id kri.ID, cmd []string, _ []byte) (string, int) { return "hi from " + id.Name, 0 }
	if err := rt.Create(e.ctx, kri.Spec{ID: kri.ID{Namespace: "dev", Name: "web", UID: s.UID}}); err != nil {
		t.Fatal(err)
	}
	_ = rt.Start(e.ctx, kri.ID{Namespace: "dev", Name: "web", UID: s.UID})
	a := &agent.Agent{Client: worker, HostName: "hv2", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.RunTunnel(e.ctx)
	for {
		var out bytes.Buffer
		c, err := e.admin.Exec(e.ctx, "dev", "web", []string{"hostname"}, nil, &out, nil)
		if code(err) == http.StatusServiceUnavailable && e.ctx.Err() == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil || c != 0 || out.String() != "hi from web" {
			t.Fatalf("admin exec: %q, %d, %v", out.String(), c, err)
		}
		break
	}
}

// With auth on, the built-in roles exist, and the cluster-admins group has cluster-admin.
func TestBuiltinRolesAreSeeded(t *testing.T) {
	e := setupAuth(t)
	for _, name := range []string{"cluster-admin", "admin", "editor", "viewer", "runner"} {
		var r v1.ClusterRole
		if err := e.admin.Get(e.ctx, "ClusterRole", "", name, &r); err != nil || len(r.Rules) == 0 {
			t.Errorf("ClusterRole %s: %v", name, err)
		}
	}
	var b v1.ClusterRoleBinding
	if err := e.admin.Get(e.ctx, "ClusterRoleBinding", "", "cluster-admins", &b); err != nil || b.Subjects[0].Name != "kevaso:cluster-admins" {
		t.Fatalf("cluster-admins binding: %+v, %v", b, err)
	}
}
