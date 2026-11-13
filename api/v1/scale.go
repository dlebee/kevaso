package v1

import "kevaso.com/core/api/meta"

// Scale is what a defined kind's scale subresource reads and writes (GET and PUT
// …/NAME/scale): the object's wanted replica count and, if the kind reports one, the current one.
// It isn't stored: it's a view of the object at its resourceVersion.
type Scale struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            ScaleSpec   `json:"spec"`
	Status          ScaleStatus `json:"status"`
}

// ScaleSpec is the wanted count.
type ScaleSpec struct {
	Replicas int64 `json:"replicas"`
}

// ScaleStatus is the current count (0 when the kind reports none yet).
type ScaleStatus struct {
	Replicas int64 `json:"replicas"`
}
