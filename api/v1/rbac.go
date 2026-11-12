package v1

import "kevaso.com/core/api/meta"

// RBAC, copied from Kubernetes (design §9.3): Roles grant verbs on resources in one namespace,
// ClusterRoles anywhere; bindings give a role to users, groups and service accounts. No binding,
// no access.

// PolicyRule allows Verbs on Resources (plural names, with subresources as "silos/exec"), optionally
// only the named objects. "*" matches anything.
type PolicyRule struct {
	Verbs         []string `json:"verbs"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// Verbs the API knows. Subresources carry the sensitive actions: create on silos/exec runs a
// command in a silo.
var Verbs = []string{"get", "list", "watch", "create", "update", "patch", "delete"}

// Role grants rules inside its namespace.
type Role struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Rules           []PolicyRule `json:"rules"`
}

// ClusterRole grants rules in every namespace and on cluster-scoped kinds (Hosts, Namespaces), or
// in one namespace when a RoleBinding refers to it.
type ClusterRole struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Rules           []PolicyRule `json:"rules"`
}

// Subject is who a binding is for.
type Subject struct {
	Kind      string `json:"kind"` // User | Group | ServiceAccount
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"` // ServiceAccount only; default: the binding's
}

// RoleRef names the role a binding grants.
type RoleRef struct {
	Kind string `json:"kind"` // Role | ClusterRole
	Name string `json:"name"`
}

// RoleBinding grants a Role or ClusterRole inside its namespace.
type RoleBinding struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	RoleRef         RoleRef   `json:"roleRef"`
	Subjects        []Subject `json:"subjects"`
}

// ClusterRoleBinding grants a ClusterRole everywhere.
type ClusterRoleBinding struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	RoleRef         RoleRef   `json:"roleRef"`
	Subjects        []Subject `json:"subjects"`
}

// ServiceAccount is an identity for CI, scripts and tools, in one namespace. Its tokens stop
// working when it's deleted.
type ServiceAccount struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
}
