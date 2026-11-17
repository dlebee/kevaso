package rbac

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Editors create and delete OpenShellPolicies in their namespace, the same verbs as Grant.
// Viewers read them and do not create them.
func TestOpenShellPoliciesFollowTheGrantRoles(t *testing.T) {
	p := builtinPolicy(
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "d"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "vw", Namespace: "d"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}, Subjects: []v1.Subject{{Kind: "User", Name: "vw"}}},
	)
	ed := Attributes{User: "ed", Groups: []string{Authenticated}, Resource: "openshellpolicies", Namespace: "d", Labels: map[string]string{}}
	for _, verb := range []string{"create", "delete", "get", "update"} {
		ed.Verb = verb
		if !p.Authorize(ed).Allowed {
			t.Errorf("editor %s openshellpolicies refused", verb)
		}
	}
	vw := Attributes{User: "vw", Groups: []string{Authenticated}, Verb: "create", Resource: "openshellpolicies", Namespace: "d", Labels: map[string]string{}}
	if p.Authorize(vw).Allowed {
		t.Fatal("viewer create openshellpolicies allowed")
	}
	vw.Verb = "get"
	if !p.Authorize(vw).Allowed {
		t.Fatal("viewer get openshellpolicies refused")
	}
	ed.Namespace = "other"
	ed.Verb = "create"
	if p.Authorize(ed).Allowed {
		t.Fatal("editor create openshellpolicies in another namespace allowed")
	}
}
