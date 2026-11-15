package v1

import (
	"slices"
	"time"

	"kevaso.com/core/api/meta"
)

// ClusterSecret is one secret for things that have no namespace: a plugin on a host (design
// hack/design/clustersecret.md). Cluster-scoped. The value is sealed the same way a Secret's is
// and never returned on get or list; a cluster-admin reads it back with --reveal, and a host
// reads it through …/clustersecrets/NAME/value when ForHost says it may.
//
// spec.delegate is left for a later feature (namespaces that may use it). v1 has no such field.
type ClusterSecret struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ClusterSecretSpec   `json:"spec,omitempty"`
	Status          ClusterSecretStatus `json:"status,omitempty"`
}

// ClusterSecretSpec is who the secret is for. Value is write-only: it's sealed and removed
// before the object is stored, so reads never carry it.
type ClusterSecretSpec struct {
	Description string `json:"description,omitempty"`
	// Plugins are the plugin install names that receive the value. Required, and never empty.
	Plugins []string `json:"plugins,omitempty"`
	// Hosts are the hosts that receive it. Empty means every host that runs one of Plugins.
	Hosts []string `json:"hosts,omitempty"`
	Value []byte   `json:"value,omitempty"` // write-only (base64 in JSON)
}

// ClusterSecretStatus is what the server records about the value, never the value itself.
// The server sets it; a caller's status is dropped on create and on update.
type ClusterSecretStatus struct {
	Version   int64      `json:"version,omitempty"` // bumps on every new value
	ChangedAt *time.Time `json:"changedAt,omitempty"`
}

// ForHost reports whether host may read this secret's value: plugins is non-empty, and hosts
// is empty or names host. host itself must be a name.
func (s *ClusterSecret) ForHost(host string) bool {
	if s == nil || host == "" || len(s.Spec.Plugins) == 0 {
		return false
	}
	if len(s.Spec.Hosts) == 0 {
		return true
	}
	return slices.Contains(s.Spec.Hosts, host)
}
