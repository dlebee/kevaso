package apiserver_test

import (
	"net/http"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A group subject system:serviceaccounts:NS names that namespace. The binding keeps the
// namespace from being deleted, the same as a service-account subject in it does. The group
// every service account shares, with no namespace, names none.
func TestAServiceAccountGroupNamesItsNamespace(t *testing.T) {
	e := setupAuth(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must(e.admin.Create(e.ctx, ns("web3")))
	must(e.admin.Create(e.ctx, ns("shop")))

	all := &v1.ClusterRoleBinding{TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "all-accounts"},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "viewer"},
		Subjects: []v1.Subject{{Kind: "Group", Name: "system:serviceaccounts"}}}
	must(e.admin.Create(e.ctx, all))
	if err := e.admin.Delete(e.ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3 while a group names every service account and no namespace: %v", err)
	}
	must(e.admin.Create(e.ctx, ns("web3")))

	other := roleBind(tm, "shop", "other-ns", v1.Subject{Kind: "Group", Name: "system:serviceaccounts:shop"})
	must(e.admin.Create(e.ctx, other))
	if err := e.admin.Delete(e.ctx, "Namespace", "", "web3"); err != nil {
		t.Fatalf("deleting web3 while a group names shop: %v", err)
	}
	must(e.admin.Create(e.ctx, ns("web3")))

	named := &v1.ClusterRoleBinding{TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "web3-accounts"},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "viewer"},
		Subjects: []v1.Subject{{Kind: "Group", Name: "system:serviceaccounts:web3"}}}
	must(e.admin.Create(e.ctx, named))
	err := e.admin.Delete(e.ctx, "Namespace", "", "web3")
	if code(err) != http.StatusConflict || !strings.Contains(err.Error(), "named from outside") || !strings.Contains(err.Error(), "1 ClusterRoleBinding (web3-accounts)") {
		t.Fatalf("deleting web3 while a group names it: %v, want 409 naming the binding", err)
	}
	var n v1.Namespace
	if err := e.admin.Get(e.ctx, "Namespace", "", "web3", &n); err != nil || n.Status.Phase != "Active" {
		t.Fatalf("web3 after the refusal: %v phase %q", err, n.Status.Phase)
	}
}
