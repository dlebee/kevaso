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
