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
var workloads = []string{"silos", "silosets", "services", "vmimages", "serviceaccounts", "grants", "ingresses", "certificates"}

// Secret powers by role: admins do everything a person can, editors can create and use secrets but
// never read a value back, viewers see that they exist.
var (
	secretsAdmin  = v1.PolicyRule{Verbs: []string{"list", v1.VerbWrite, v1.VerbUse, v1.VerbReadValue, v1.VerbApprove}, Resources: []string{"secrets"}}
	secretsEditor = v1.PolicyRule{Verbs: []string{"list", v1.VerbWrite, v1.VerbUse}, Resources: []string{"secrets"}}
	secretsViewer = v1.PolicyRule{Verbs: []string{"list"}, Resources: []string{"secrets"}}
)

// Approvals (design §8.7) and panes (§10.1): everyone with a role in the namespace sees the queue; admins also answer
// (approve on secrets, above) and clear old ones. Nobody creates them: the broker does.
var (
	approvalsRead  = v1.PolicyRule{Verbs: read, Resources: []string{"approvals", "panes", "leases"}}
	approvalsAdmin = v1.PolicyRule{Verbs: []string{"get", "list", "watch", "delete"}, Resources: []string{"approvals", "panes", "leases"}}
)

// Port leases (design §7.2d): editors may open and close a silo's leased ports (within the exposure
// an admin made); admins also answer the leases that need a yes. Both on silos/exposure.
var (
	exposureEditor = v1.PolicyRule{Verbs: []string{v1.VerbOpen}, Resources: []string{v1.ResourceExposure}}
	exposureAdmin  = v1.PolicyRule{Verbs: []string{v1.VerbOpen, v1.VerbApprove}, Resources: []string{v1.ResourceExposure}}
)

// IPs (design §7.2c-1): an address costs money and is what peers point at, so admins reserve
// and release them (and use them); editors may put a silo they edit on one an admin made (use),
// and see them; viewers see them. Naming an IP in a service needs use on it, like a secret.
var (
	ipsAdmin  = v1.PolicyRule{Verbs: append(slices.Clone(write), v1.VerbUse), Resources: []string{"ips"}}
	ipsEditor = v1.PolicyRule{Verbs: append(slices.Clone(read), v1.VerbUse), Resources: []string{"ips"}}
	ipsViewer = v1.PolicyRule{Verbs: read, Resources: []string{"ips"}}
)

// siloShell is a terminal in a silo (create silos/ssh, kvo ssh) and its files (get silos/files to
// read, create to write: kvo cp, kvo ui): as strong as exec, so the same roles have it.
var (
	siloShell = v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/ssh"}}
	siloFiles = v1.PolicyRule{Verbs: []string{"get", "create"}, Resources: []string{"silos/files"}}
)

// BuiltinRoles are the roles of design §9.3: cluster-admin (everything), admin (a namespace, its
// roles included, and exposing silos publicly), editor (workloads, exec; not public exposure),
// viewer (read workloads), runner (runs).
func BuiltinRoles() []*v1.ClusterRole {
	mk := func(name string, rules ...v1.PolicyRule) *v1.ClusterRole {
		return &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"},
			ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{BuiltinLabel: "true"}}, Rules: rules}
	}
	return []*v1.ClusterRole{
		mk("cluster-admin", v1.PolicyRule{Verbs: []string{"*"}, Resources: []string{"*"}}),
		mk("admin",
			v1.PolicyRule{Verbs: write, Resources: slices.Concat(workloads, []string{"roles", "rolebindings"})},
			v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/exec", "silos/move", "serviceaccounts/token", "services/expose-public", "ingresses/publish-public"}},
			siloShell, siloFiles, secretsAdmin, approvalsAdmin, exposureAdmin, ipsAdmin),
		mk("editor",
			v1.PolicyRule{Verbs: write, Resources: workloads},
			v1.PolicyRule{Verbs: []string{"create"}, Resources: []string{"silos/exec", "silos/move", "serviceaccounts/token"}},
			siloShell, siloFiles, secretsEditor, approvalsRead, exposureEditor, ipsEditor),
		mk("viewer", v1.PolicyRule{Verbs: read, Resources: workloads}, secretsViewer, approvalsRead, ipsViewer),
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
