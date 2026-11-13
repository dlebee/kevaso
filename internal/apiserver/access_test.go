package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/issuer"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// accessEnv is a cluster with an issuer (people, service accounts), an admin listener and a TLS one.
type accessEnv struct {
	*authEnv
	iss *issuer.Issuer
}

func setupAccess(t *testing.T) *accessEnv {
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
	iss, err := issuer.New(ctx, st, clock.Real{}, "https://placeholder")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apiserver.NewWithAuth(st, clock.Real{}, &apiserver.Auth{CA: ca, Tokens: tokens, Issuer: iss})
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
	iss.URL = ts.URL
	as := httptest.NewUnstartedServer(srv) // stands for the admin socket
	as.Config = srv.HTTPServer(true)
	as.Start()
	t.Cleanup(as.Close)
	return &accessEnv{authEnv: &authEnv{url: ts.URL, ca: ca, tokens: tokens, admin: client.New(as.URL), ctx: ctx}, iss: iss}
}

func accessTM(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

// serviceAccount makes NS/NAME (and the namespace) and a client signed in as it.
func (e *accessEnv) serviceAccount(t *testing.T, nsName, name string) *client.Client {
	t.Helper()
	if err := e.admin.Create(e.ctx, ns(nsName)); err != nil && !client.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.ServiceAccount{TypeMeta: accessTM("ServiceAccount"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: nsName}}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := e.iss.ServiceAccountToken(e.ctx, nsName, name, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c := e.tlsClient(t, nil)
	c.Token = func(context.Context) (string, error) { return tok, nil }
	return c
}

func (e *accessEnv) grant(t *testing.T, name, saNS, sa string, rules ...v1.PolicyRule) {
	t.Helper()
	if err := e.admin.Create(e.ctx, &v1.ClusterRole{TypeMeta: accessTM("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.ClusterRoleBinding{TypeMeta: accessTM("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: name},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: name}, Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: sa, Namespace: saNS}}}); err != nil {
		t.Fatal(err)
	}
}

// K-003: invites and join tokens are people's: a service account (a plugin's controller) gets
// 403 even when a role (one written before the install check) names them.
func TestServiceAccountsNeverMintInvitesOrJoinTokens(t *testing.T) {
	e := setupAccess(t)
	plugin := e.serviceAccount(t, "kevaso-plugins", "plugin-x")
	e.grant(t, "x-ops", "kevaso-plugins", "plugin-x",
		v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"invites", "jointokens"}})
	var inv client.InviteResponse
	err := plugin.Call(e.ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: "m", Groups: []string{"kevaso:cluster-admins"}}, &inv)
	if code(err) != http.StatusForbidden || inv.Code != "" {
		t.Errorf("invite by a service account: %v (code issued: %v), want 403", err, inv.Code != "")
	}
	var jt client.JoinTokenResponse
	err = plugin.Call(e.ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "h", Roles: []string{"system-node"}}, &jt)
	if code(err) != http.StatusForbidden || jt.Token != "" {
		t.Errorf("join token by a service account: %v (token issued: %v), want 403", err, jt.Token != "")
	}
}

// K-011: a user certificate is never the admin socket, whatever its name (root is what kvoadm
// init names the first one when run as root).
func TestUserCertificateNamedRootIsNotTheAdminSocket(t *testing.T) {
	e := setupAccess(t)
	cred, err := e.admin.IssueUserCert(e.ctx, "root")
	if err == nil {
		root := e.tlsClient(t, &cred)
		if _, err := root.IssueUserCert(e.ctx, "mallory"); code(err) != http.StatusForbidden {
			t.Errorf("a certificate named root minting a certificate over TLS: %v, want 403", err)
		}
	}
	if apiserver.LocalAdmin.Validate() == nil || apiserver.Component.Validate() == nil {
		t.Errorf("%v could be written into a certificate", apiserver.LocalAdmin)
	}
}

// ciUser makes the service account NS/ci, who may create and update silos and silosets in NS but
// holds no use on any secret.
func (e *accessEnv) ciUser(t *testing.T, nsName string) *client.Client {
	t.Helper()
	c := e.serviceAccount(t, nsName, "ci")
	if err := e.admin.Create(e.ctx, &v1.Role{TypeMeta: accessTM("Role"), ObjectMeta: meta.ObjectMeta{Name: "ci", Namespace: nsName}, Rules: []v1.PolicyRule{
		{Verbs: []string{"get", "list", "create", "update"}, Resources: []string{"silos", "silosets"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.RoleBinding{TypeMeta: accessTM("RoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "ci", Namespace: nsName},
		RoleRef: v1.RoleRef{Kind: "Role", Name: "ci"}, Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "ci"}}}); err != nil {
		t.Fatal(err)
	}
	return c
}

// K-012: a SiloSet's template takes a Grant only if its author may use the secrets the Grant
// names, as a Silo does; on create and on an update that adds one.
func TestSiloSetTemplateGrantsNeedUse(t *testing.T) {
	e := setupAccess(t)
	u := e.ciUser(t, "dev")
	if err := e.admin.Create(e.ctx, &v1.Secret{TypeMeta: accessTM("Secret"), ObjectMeta: meta.ObjectMeta{Name: "prod-db", Namespace: "dev"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Create(e.ctx, &v1.Grant{TypeMeta: accessTM("Grant"), ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{{Name: "prod-db"}}}}); err != nil {
		t.Fatal(err)
	}
	s := newSilo("direct")
	s.Spec.Grants = []string{"db"}
	if err := u.Create(e.ctx, s); code(err) != http.StatusForbidden {
		t.Fatalf("control, a silo with the grant: %v, want 403", err)
	}
	set := func(name string, grants ...string) *v1.SiloSet {
		tmpl := newSilo("x").Spec
		tmpl.Grants = grants
		return &v1.SiloSet{TypeMeta: accessTM("SiloSet"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "dev"},
			Spec: v1.SiloSetSpec{Instances: 1, Template: v1.SiloTemplate{SiloSpec: tmpl}}}
	}
	if err := u.Create(e.ctx, set("viaset", "db")); code(err) != http.StatusForbidden {
		t.Errorf("a siloset whose template has the grant: %v, want 403", err)
	}
	// An update that adds the grant is refused too; a set without grants is fine.
	if err := u.Create(e.ctx, set("plain")); err != nil {
		t.Fatalf("a siloset without grants: %v", err)
	}
	next := &v1.SiloSet{}
	if err := u.Get(e.ctx, "SiloSet", "dev", "plain", next); err != nil {
		t.Fatal(err)
	}
	next.Spec.Template.Grants = []string{"db"}
	if err := u.Update(e.ctx, next); code(err) != http.StatusForbidden {
		t.Errorf("an update adding the grant to a siloset: %v, want 403", err)
	}
}
