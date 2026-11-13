package v1

import "kevaso.com/core/api/meta"

// Admission policies (design §4.1, ADR 0005): CEL rules for any kind, in process, no webhooks.
// Both are cluster-scoped. They never apply to themselves or to the RBAC kinds, nor to /status
// writes or deletes. CEL sees `object`, `oldObject` (null on create) and `request` (user, groups,
// verb, operation, namespace, name, kind, resource).

// Operations a policy can match.
const (
	OperationCreate = "CREATE"
	OperationUpdate = "UPDATE"
)

// PolicyMatch says which writes a policy covers.
type PolicyMatch struct {
	// Kinds: a built-in kind's name or plural (Silo, silos), a defined kind's resource
	// (databases.acme.dev), or "*".
	Kinds []string `json:"kinds"`
	// Namespaces: empty matches every namespace and cluster-scoped objects; otherwise only objects
	// in these namespaces.
	Namespaces []string `json:"namespaces,omitempty"`
	// Operations: CREATE, UPDATE; empty is both.
	Operations []string `json:"operations,omitempty"`
}

// ValidationPolicy refuses writes its expressions say no to. Every matching policy runs, in name
// order; a write is refused with every failure.
type ValidationPolicy struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ValidationPolicySpec `json:"spec"`
}

// ValidationPolicySpec is what to check, and on what.
type ValidationPolicySpec struct {
	Match       PolicyMatch        `json:"match"`
	Validations []PolicyValidation `json:"validations"`
}

// PolicyValidation is a CEL expression that must be true.
type PolicyValidation struct {
	Expression string `json:"expression"`
	Message    string `json:"message,omitempty"`
}

// MutationPolicy sets fields before validation. Matching policies run in name order, each mutation
// in list order, each seeing what the ones before left.
type MutationPolicy struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            MutationPolicySpec `json:"spec"`
}

// MutationPolicySpec is what to set, and on what.
type MutationPolicySpec struct {
	Match     PolicyMatch `json:"match"`
	Mutations []Mutation  `json:"mutations"`
}

// Mutation sets one field.
type Mutation struct {
	// Field is a dotted path: spec.size, spec.limits.cpu, metadata.labels.KEY,
	// metadata.annotations.KEY. Never apiVersion, kind, the rest of metadata, or status.
	Field string `json:"field"`
	// Value is CEL; null removes the field.
	Value string `json:"value"`
	// When, if set, is CEL: the mutation applies only when it's true.
	When string `json:"when,omitempty"`
}
