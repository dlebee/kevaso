package rbac

import (
	"slices"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// BuiltinLabel marks the roles and bindings the control plane creates (and keeps).
const BuiltinLabel = "kevaso.com/builtin"

var (
	read  = []string{"get", "list", "watch"}
	write = []string{"get", "list", "watch", "create", "update", "patch", "delete"}
)

// workloads is what lives in a namespace and its users work with.
var workloads = []string{"silos", "serviceaccounts"}

// BuiltinRoles are the roles of design §9.3: cluster-admin (everything), admin (a namespace, its
// roles included), editor (workloads, exec), viewer (read workloads), runner (runs).
func BuiltinRoles() []*v1.ClusterRole {
	mk := func(name string, rules ...v1.PolicyRule) *v1.ClusterRole {
		return &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"},
			ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{BuiltinLabel: "true"}}, Rules: rules}
	}
	return []*v1.ClusterRole{
		mk("cluster-admin", v1.PolicyRule{Verbs: []string{"*"}, Resources: []string{"*"}}),
		mk("admin",
			v1.PolicyRule{Verbs: write, Resources: slices.Concat(workloads, []string{"roles", "rolebindings"})},
			v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/exec", "serviceaccounts/token"}}),
		mk("editor",
			v1.PolicyRule{Verbs: write, Resources: workloads},
			v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/exec", "serviceaccounts/token"}}),
		mk("viewer", v1.PolicyRule{Verbs: read, Resources: workloads}),
		mk("runner", v1.PolicyRule{Verbs: []string{"get", "list", "watch", "create"}, Resources: []string{"runs"}}),
	}
}

// BuiltinBindings: the cluster-admins group has cluster-admin.
func BuiltinBindings() []*v1.ClusterRoleBinding {
	return []*v1.ClusterRoleBinding{{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"},
		ObjectMeta: meta.ObjectMeta{Name: "cluster-admins", Labels: map[string]string{BuiltinLabel: "true"}},
		RoleRef:    v1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects:   []v1.Subject{{Kind: "Group", Name: ClusterAdmins}},
	}}
}
