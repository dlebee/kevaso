package v1

import (
	"time"

	"kevaso.com/core/api/meta"
)

// ClusterSecret is one secret for things that have no namespace: a plugin on a host (design
// hack/design/clustersecret.md). Cluster-scoped. The value is sealed the same way a Secret's is
// and never returned on get or list. Who may read it is a ClusterRole pinned to the name
// (clustersecrets/value), not a field of this object.
//
// spec.delegate is left for a later feature (namespaces that may use it). v1 has no such field.
type ClusterSecret struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ClusterSecretSpec   `json:"spec,omitempty"`
	Status          ClusterSecretStatus `json:"status,omitempty"`
}

// ClusterSecretSpec is the secret's description. Value is write-only: it's sealed and removed
// before the object is stored, so reads never carry it.
type ClusterSecretSpec struct {
	Description string `json:"description,omitempty"`
	Value       []byte `json:"value,omitempty"` // write-only (base64 in JSON)
}

// ClusterSecretStatus is what the server records about the value, never the value itself.
// The server sets it; a caller's status is dropped on create and on update.
type ClusterSecretStatus struct {
	Version   int64      `json:"version,omitempty"` // bumps on every new value
	ChangedAt *time.Time `json:"changedAt,omitempty"`
}
