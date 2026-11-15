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
			{Verbs: []string{"*"}, Resources: []string{"clustersecrets", "clustersecrets/value", "secrets"}},
		}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "web3"},
			RoleRef:  v1.RoleRef{Kind: "Role", Name: "r"},
			Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}},
	})
	for _, verb := range []string{"get", "list", "watch", "create", "update", "patch", "delete"} {
		if p.Authorize(Attributes{User: "ada", Verb: verb, Resource: "clustersecrets", Name: "k"}).Allowed {
			t.Errorf("namespaced role allowed %s clustersecrets", verb)
		}
		if p.Authorize(Attributes{User: "ada", Verb: verb, Resource: ClusterSecretValue, Name: "k"}).Allowed {
			t.Errorf("namespaced role allowed %s clustersecrets/value", verb)
		}
	}
	if !p.Authorize(Attributes{User: "ada", Verb: "get", Resource: "secrets", Namespace: "web3", Name: "k"}).Allowed {
		t.Fatal("the role no longer grants secrets in its namespace: the binding isn't what this test thinks")
	}
}

// A cluster secret's value is always pinned. Empty resourceNames grants nothing, including when
// the rule is "*" ; a name grants that object and not another. Removing the pin lets the unpinned
// rules below succeed.
func TestClusterSecretValueIsPinned(t *testing.T) {
	sa := ServiceAccountUser("kevaso-system", "plugin-juicefs")
	pinned := NewPolicy([]meta.Object{
		&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "juicefs"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get"}, Resources: []string{ClusterSecretValue}, ResourceNames: []string{"bucket", "metering"}},
		}},
		&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "juicefs"},
			RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "juicefs"},
			Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "plugin-juicefs", Namespace: "kevaso-system"}}},
	})
	for _, name := range []string{"bucket", "metering"} {
		if !pinned.Authorize(Attributes{User: sa, Verb: "get", Resource: ClusterSecretValue, Name: name}).Allowed {
			t.Errorf("pinned role refused %s", name)
		}
	}
	if pinned.Authorize(Attributes{User: sa, Verb: "get", Resource: ClusterSecretValue, Name: "other"}).Allowed {
		t.Fatal("pinned role allowed a name it doesn't list")
	}
	if pinned.Authorize(Attributes{User: sa, Verb: "get", Resource: ClusterSecretValue}).Allowed {
		t.Fatal("pinned role allowed a read with no name")
	}

	// The same rule through a RoleBinding never reaches a cluster-scoped read.
	namespaced := NewPolicy([]meta.Object{
		&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "juicefs"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get"}, Resources: []string{ClusterSecretValue}, ResourceNames: []string{"bucket"}},
		}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "juicefs", Namespace: "kevaso-system"},
			RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "juicefs"},
			Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "plugin-juicefs", Namespace: "kevaso-system"}}},
	})
	if namespaced.Authorize(Attributes{User: sa, Verb: "get", Resource: ClusterSecretValue, Name: "bucket"}).Allowed {
		t.Fatal("a RoleBinding granted a cluster secret's value")
	}

	for _, rules := range [][]v1.PolicyRule{
		{{Verbs: []string{"get"}, Resources: []string{ClusterSecretValue}}},
		{{Verbs: []string{"*"}, Resources: []string{ClusterSecretValue}}},
		{{Verbs: []string{"get"}, Resources: []string{"*"}}},
		{{Verbs: []string{"*"}, Resources: []string{"*"}}},
	} {
		p := NewPolicy([]meta.Object{
			&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "open"}, Rules: rules},
			&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "open"},
				RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "open"},
				Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "plugin-juicefs", Namespace: "kevaso-system"}}},
		})
		if p.Authorize(Attributes{User: sa, Verb: "get", Resource: ClusterSecretValue, Name: "bucket"}).Allowed {
			t.Fatalf("unpinned rule %+v granted a value", rules)
		}
	}

	// The pin is the value only. get on the object, pinned or not, is unchanged.
	objects := NewPolicy([]meta.Object{
		&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "see"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"get", "list"}, Resources: []string{"clustersecrets"}},
		}},
		&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "see"},
			RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "see"},
			Subjects: []v1.Subject{{Kind: "User", Name: "cara"}}},
	})
	if !objects.Authorize(Attributes{User: "cara", Verb: "get", Resource: "clustersecrets", Name: "bucket"}).Allowed {
		t.Fatal("get on clustersecrets was pinned when it isn't")
	}
	if !objects.Authorize(Attributes{User: "cara", Verb: "list", Resource: "clustersecrets"}).Allowed {
		t.Fatal("list on clustersecrets was refused")
	}
	if objects.Authorize(Attributes{User: "cara", Verb: "get", Resource: ClusterSecretValue, Name: "bucket"}).Allowed {
		t.Fatal("get on the object granted its value")
	}
}
