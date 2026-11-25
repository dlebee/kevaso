package integration

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/invite"
	"kevaso.com/core/internal/login"
	"kevaso.com/core/internal/tokenstore"
)

// K-058: an invite names the user and the groups it signs in with, so whoever creates one could
// make a cluster-admin, or sign in as an existing user. Creating invites is for cluster-admins
// only, by definition: a person whose role names create invites, and nothing else, is refused,
// and told who can do it.
func TestK058OnlyAClusterAdminCreatesInvites(t *testing.T) {
	c := newCluster(t)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.admin.Create(c.ctx, &v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "inviter"},
		Rules: []v1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"invites"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.ClusterRoleBinding{TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "carol"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "inviter"}, Subjects: []v1.Subject{{Kind: "User", Name: "carol"}}}); err != nil {
		t.Fatal(err)
	}
	fp, _ := client.Fingerprint(c.ca)
	caPEM, err := login.FetchCA(c.ctx, c.url, fp)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := login.Login(c.ctx, c.url, caPEM, login.Options{Open: browser(t, c.invite(t, "carol"))})
	if err != nil {
		t.Fatal(err)
	}
	st := tokenstore.File{Dir: t.TempDir()}
	if err := login.Save(st, "it", tok); err != nil {
		t.Fatal(err)
	}
	carol, _ := client.NewTLS(c.url, caPEM, nil, nil)
	carol.Token = login.Tokens(c.url, caPEM, st, "it", t.TempDir())

	var inv client.InviteResponse
	err = carol.Call(c.ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: "eve", Groups: []string{"kevaso:cluster-admins"}}, &inv)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden || inv.Code != "" {
		t.Fatalf("an invite by a non-cluster-admin whose role names create invites: %v (code issued: %v), want 403", err, inv.Code != "")
	}
	if !strings.Contains(ce.Message, "cluster-admin") || !strings.Contains(ce.Message, "kvoadm users invite") {
		t.Errorf("the refusal doesn't say who can: %q", ce.Message)
	}
	// A cluster-admin still can.
	if code := c.invite(t, "eve"); code == "" {
		t.Fatal("a cluster-admin's invite: no code")
	}
}

// kvo invite: a cluster-admin signed in with kvo login (a person's session, no admin certificate,
// no SSH) invites someone with a role in a namespace, and that person signs in with the code.
func TestAClusterAdminSignedInWithKvoInvitesSomeone(t *testing.T) {
	c := newCluster(t)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.admin.Create(c.ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "payments"}}); err != nil {
		t.Fatal(err)
	}
	fp, _ := client.Fingerprint(c.ca)
	caPEM, err := login.FetchCA(c.ctx, c.url, fp)
	if err != nil {
		t.Fatal(err)
	}
	signIn := func(code string) *client.Client {
		tok, err := login.Login(c.ctx, c.url, caPEM, login.Options{Open: browser(t, code)})
		if err != nil {
			t.Fatal(err)
		}
		st := tokenstore.File{Dir: t.TempDir()}
		if err := login.Save(st, "it", tok); err != nil {
			t.Fatal(err)
		}
		cl, _ := client.NewTLS(c.url, caPEM, nil, nil)
		cl.Token = login.Tokens(c.url, caPEM, st, "it", t.TempDir())
		return cl
	}
	ann := signIn(c.invite(t, "ann", "kevaso:cluster-admins"))

	var out strings.Builder
	if err := invite.Create(c.ctx, ann, c.url, invite.Request{User: "bob", Namespace: "payments"}, &out); err != nil {
		t.Fatalf("a cluster-admin's kvo invite: %v", err)
	}
	printed := out.String()
	code := ""
	for _, l := range strings.Split(printed, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "invite code: "); ok {
			code = v
		}
	}
	if code == "" || !strings.Contains(printed, "kvo login "+c.url+" --ca "+fp) || !strings.Contains(printed, "bob is editor in namespace payments") {
		t.Fatalf("what to send bob:\n%s", printed)
	}
	bob := signIn(code)
	var silos struct{ Items []v1.Silo }
	if err := bob.Call(c.ctx, http.MethodGet, "/apis/kevaso/v1/namespaces/payments/silos", nil, &silos); err != nil {
		t.Fatalf("bob, an editor in payments, lists its silos: %v", err)
	}
	var none client.InviteResponse
	err = bob.Call(c.ctx, http.MethodPost, "/admin/invites", client.InviteRequest{User: "eve"}, &none)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden {
		t.Fatalf("bob (not a cluster-admin) invites: %v, want 403", err)
	}
	if !strings.Contains(ce.Message, "kvo invite") {
		t.Errorf("the refusal doesn't name kvo invite: %q", ce.Message)
	}
}
