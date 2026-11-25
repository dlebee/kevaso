package integration

import (
	"errors"
	"fmt"
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
	if err := invite.Create(c.ctx, ann, c.url, invite.Request{User: "bob", Namespace: "payments", Role: "clusterrole/editor"}, &out); err != nil {
		t.Fatalf("a cluster-admin's kvo invite: %v", err)
	}
	printed := out.String()
	code := ""
	for _, l := range strings.Split(printed, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "invite code: "); ok {
			code = v
		}
	}
	if code == "" || !strings.Contains(printed, "kvo login "+c.url+" --ca "+fp) || !strings.Contains(printed, "bob has the ClusterRole editor in namespace payments") {
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

// An invite's role says what it is and where it applies, every time: a Role in a namespace, a
// ClusterRole in a namespace, or a ClusterRole everywhere. A missing Role, or a caller who may
// not invite, leaves nothing behind: no binding, no code.
func TestInviteRolesAreExplicit(t *testing.T) {
	c := newCluster(t)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.admin.Create(c.ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "payments"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, &v1.Role{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "deployer", Namespace: "payments"},
		Rules: []v1.PolicyRule{{Verbs: []string{"get", "list"}, Resources: []string{"silos"}}}}); err != nil {
		t.Fatal(err)
	}
	run := func(r invite.Request) (string, error) {
		var out strings.Builder
		err := invite.Create(c.ctx, c.admin, c.url, r, &out)
		return out.String(), err
	}
	for _, x := range []struct {
		r    invite.Request
		says string
		get  func() error
	}{
		{invite.Request{User: "ann", Namespace: "payments", Role: "role/deployer"}, "ann has the Role deployer in namespace payments",
			func() error {
				var b v1.RoleBinding
				if err := c.admin.Get(c.ctx, "RoleBinding", "payments", "ann-role-deployer", &b); err != nil {
					return err
				}
				if b.RoleRef != (v1.RoleRef{Kind: "Role", Name: "deployer"}) {
					return fmt.Errorf("roleRef %+v", b.RoleRef)
				}
				return nil
			}},
		{invite.Request{User: "bob", Namespace: "payments", Role: "clusterrole/editor"}, "bob has the ClusterRole editor in namespace payments",
			func() error {
				var b v1.RoleBinding
				if err := c.admin.Get(c.ctx, "RoleBinding", "payments", "bob-clusterrole-editor", &b); err != nil {
					return err
				}
				if b.RoleRef != (v1.RoleRef{Kind: "ClusterRole", Name: "editor"}) {
					return fmt.Errorf("roleRef %+v", b.RoleRef)
				}
				return nil
			}},
		{invite.Request{User: "cat", ClusterRole: "viewer"}, "cat has the ClusterRole viewer in every namespace",
			func() error {
				var b v1.ClusterRoleBinding
				if err := c.admin.Get(c.ctx, "ClusterRoleBinding", "", "cat-clusterrole-viewer", &b); err != nil {
					return err
				}
				if b.RoleRef != (v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}) || len(b.Subjects) != 1 || b.Subjects[0].Name != "cat" {
					return fmt.Errorf("binding %+v", b)
				}
				return nil
			}},
		{invite.Request{User: "dan"}, "dan has no role yet", func() error { return nil }},
	} {
		out, err := run(x.r)
		if err != nil || !strings.Contains(out, x.says) || !strings.Contains(out, "invite code: kvi_") {
			t.Fatalf("%+v: %v\n%s", x.r, err, out)
		}
		if err := x.get(); err != nil {
			t.Errorf("%+v: the binding: %v", x.r, err)
		}
	}

	// A Role that isn't there: refused before any code is made.
	if out, err := run(invite.Request{User: "eve", Namespace: "payments", Role: "role/nosuch"}); err == nil ||
		!strings.Contains(err.Error(), "no Role nosuch in namespace payments") || strings.Contains(out, "invite code") {
		t.Fatalf("a missing Role: %v\n%s", err, out)
	}

	// Someone who may not invite (bob, an editor in payments): a 403, and no binding made for eve.
	fp, _ := client.Fingerprint(c.ca)
	caPEM, err := login.FetchCA(c.ctx, c.url, fp)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := login.Login(c.ctx, c.url, caPEM, login.Options{Open: browser(t, c.invite(t, "bob"))})
	if err != nil {
		t.Fatal(err)
	}
	st := tokenstore.File{Dir: t.TempDir()}
	if err := login.Save(st, "it", tok); err != nil {
		t.Fatal(err)
	}
	bob, _ := client.NewTLS(c.url, caPEM, nil, nil)
	bob.Token = login.Tokens(c.url, caPEM, st, "it", t.TempDir())
	var out strings.Builder
	err = invite.Create(c.ctx, bob, c.url, invite.Request{User: "eve", Namespace: "payments", Role: "clusterrole/editor"}, &out)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusForbidden || !strings.Contains(ce.Message, "cluster-admin") {
		t.Fatalf("bob inviting: %v", err)
	}
	var rb v1.RoleBinding
	if err := c.admin.Get(c.ctx, "RoleBinding", "payments", "eve-clusterrole-editor", &rb); !client.IsNotFound(err) {
		t.Fatalf("a refused invite left a binding: %v", err)
	}
}
