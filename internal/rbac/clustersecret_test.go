package rbac

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A namespaced role, even one that names clustersecrets, never grants them: a ClusterSecret has
// no namespace, and a RoleBinding only applies inside its own.
func TestNamespacedRoleCannotGrantClusterSecret(t *testing.T) {
	p := NewPolicy([]meta.Object{
		&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "r", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"*"}, Resources: []string{"clustersecrets", "secrets"}},
		}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "web3"},
			RoleRef:  v1.RoleRef{Kind: "Role", Name: "r"},
			Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}},
	})
	for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete", v1.VerbReadValue, v1.VerbWrite} {
		if p.Authorize(Attributes{User: "ada", Verb: verb, Resource: "clustersecrets", Name: "k"}).Allowed {
			t.Errorf("namespaced role allowed %s clustersecrets", verb)
		}
	}
	if !p.Authorize(Attributes{User: "ada", Verb: "get", Resource: "secrets", Namespace: "web3", Name: "k"}).Allowed {
		t.Fatal("the role no longer grants secrets in its namespace: the binding isn't what this test thinks")
	}
}
