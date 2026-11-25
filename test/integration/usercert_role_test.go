package integration

import (
	"errors"
	"net/http"
	"testing"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/pki"
)

func forbidden(err error) bool {
	var e *client.Error
	return errors.As(err, &e) && e.Code == http.StatusForbidden
}

// kvoadm init's kvo user: a certificate with role user has no power of its own. Bound to editor it
// does daily work in namespaces, and nothing an admin does: no admin endpoints, no certificates,
// no binding itself higher, no hosts. Renewing keeps it a user. The admin socket issues no other
// role to a user.
func TestUserRoleCertificateIsOnlyWhatRBACBinds(t *testing.T) {
	c := newCluster(t)
	ctx := c.ctx
	_ = c.admin.Create(ctx, ns("default"))
	key, csr, _ := client.NewKeyAndCSR("dana")
	cert, ca, err := c.admin.SignUserCSRAs(ctx, "dana", "user", csr)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := pki.IdentityOfPEM(cert); err != nil || id.Type != "user" || id.Name != "dana" || id.Role != "user" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	dana, err := client.NewTLS(c.url, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}

	// Unbound: nothing at all.
	if err := dana.Create(ctx, silo("early", "default")); !forbidden(err) {
		t.Fatalf("an unbound user created a silo: %v", err)
	}

	// Bound to editor, as kvoadm init does.
	b := &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "kvo-user-dana"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"},
		Subjects: []v1.Subject{{Kind: "User", Name: "dana"}}}
	if err := c.admin.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := dana.Create(ctx, silo("work", "default")); err != nil {
		t.Fatalf("editor's daily work: %v", err)
	}
	var got v1.Silo
	if err := dana.Get(ctx, "Silo", "default", "work", &got); err != nil {
		t.Fatalf("reading its silo: %v", err)
	}
	if err := dana.Delete(ctx, "Silo", "default", "work", client.Precondition{}); err != nil {
		t.Fatalf("deleting its silo: %v", err)
	}

	// Nothing an admin does.
	if err := dana.Create(ctx, ns("mine")); !forbidden(err) {
		t.Fatalf("a user created a namespace: %v", err)
	}
	if _, err := dana.List(ctx, "Host", ""); !forbidden(err) {
		t.Fatalf("a user listed hosts: %v", err)
	}
	up := &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "dana-up"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []v1.Subject{{Kind: "User", Name: "dana"}}}
	if err := dana.Create(ctx, up); !forbidden(err) {
		t.Fatalf("a user bound itself to cluster-admin: %v", err)
	}
	var users any
	if err := dana.Call(ctx, http.MethodGet, "/admin/users", nil, &users); !forbidden(err) {
		t.Fatalf("a user read /admin/users: %v", err)
	}
	if err := dana.Call(ctx, http.MethodPost, "/admin/join-tokens", client.JoinTokenRequest{Host: "x", Roles: []string{"worker"}}, &users); !forbidden(err) {
		t.Fatalf("a user made a join token: %v", err)
	}
	_, csr2, _ := client.NewKeyAndCSR("dana")
	if _, _, err := dana.SignUserCSRAs(ctx, "dana", "", csr2); !forbidden(err) {
		t.Fatalf("a user minted a certificate over TLS: %v", err)
	}

	// Renewing keeps the role.
	cred, err := dana.Renew(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := pki.IdentityOfPEM(cred.Certificate); id.Role != "user" {
		t.Fatalf("renewed as %+v", id)
	}

	// The admin socket issues cluster-admin or user, nothing else.
	for _, role := range []string{"control-plane", "worker", "admin"} {
		_, csr3, _ := client.NewKeyAndCSR("eve")
		if _, _, err := c.admin.SignUserCSRAs(ctx, "eve", role, csr3); err == nil {
			t.Fatalf("a user certificate with role %s", role)
		}
	}
}
