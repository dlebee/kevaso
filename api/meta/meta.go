// Package meta holds what every Kevaso object has, the Kubernetes way: apiVersion and kind, metadata
// (name, namespace, labels, annotations, owners, finalizers, versions) and status conditions.
package meta

import (
	"fmt"
	"regexp"
	"time"
)

// TypeMeta says what an object is.
type TypeMeta struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
}

// GetTypeMeta returns the type metadata.
func (t *TypeMeta) GetTypeMeta() *TypeMeta { return t }

// ObjectMeta is the metadata of every object.
type ObjectMeta struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	// UID is unique for the object's whole life; a deleted and re-created object gets a new one.
	UID string `json:"uid,omitempty"`
	// ResourceVersion is the store revision of the last write, as a string (opaque to clients).
	// Sending it back on update makes the update conditional (optimistic concurrency).
	ResourceVersion string `json:"resourceVersion,omitempty"`
	// Generation increases on every change to spec; status writes don't change it.
	Generation        int64             `json:"generation,omitempty"`
	CreationTimestamp *time.Time        `json:"creationTimestamp,omitempty"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
	// Finalizers block deletion until each one is removed by the controller that owns it.
	Finalizers []string `json:"finalizers,omitempty"`
}

// GetObjectMeta returns the object metadata.
func (m *ObjectMeta) GetObjectMeta() *ObjectMeta { return m }

// OwnerReference points at an object this one belongs to; deleting the owner deletes it.
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Controller bool   `json:"controller,omitempty"`
}

// Object is anything the API stores.
type Object interface {
	GetTypeMeta() *TypeMeta
	GetObjectMeta() *ObjectMeta
}

// ConditionStatus is True, False or Unknown.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// Condition is one aspect of an object's state, e.g. Ready or InitFailed.
type Condition struct {
	Type               string          `json:"type"`
	Status             ConditionStatus `json:"status"`
	Reason             string          `json:"reason,omitempty"`
	Message            string          `json:"message,omitempty"`
	ObservedGeneration int64           `json:"observedGeneration,omitempty"`
	LastTransitionTime time.Time       `json:"lastTransitionTime"`
}

// SetCondition adds or updates a condition. LastTransitionTime only moves when Status changes, so
// "how long has it been Ready" stays meaningful. It reports whether anything changed.
func SetCondition(conds *[]Condition, c Condition, now time.Time) bool {
	for i := range *conds {
		cur := &(*conds)[i]
		if cur.Type != c.Type {
			continue
		}
		if cur.Status == c.Status && cur.Reason == c.Reason && cur.Message == c.Message &&
			cur.ObservedGeneration == c.ObservedGeneration {
			return false
		}
		if cur.Status != c.Status {
			cur.LastTransitionTime = now
		}
		cur.Status, cur.Reason, cur.Message, cur.ObservedGeneration = c.Status, c.Reason, c.Message, c.ObservedGeneration
		return true
	}
	c.LastTransitionTime = now
	*conds = append(*conds, c)
	return true
}

// FindCondition returns the condition of that type, or nil.
func FindCondition(conds []Condition, typ string) *Condition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}

// IsTrue reports whether the condition of that type exists and is True.
func IsTrue(conds []Condition, typ string) bool {
	c := FindCondition(conds, typ)
	return c != nil && c.Status == ConditionTrue
}

var nameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidateName checks a DNS-label name (what Kubernetes uses for most objects): 1-63 lowercase
// letters, digits and dashes, starting and ending with a letter or digit.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 63 || !nameRE.MatchString(name) {
		return fmt.Errorf("name %q: want 1-63 lowercase letters, digits or '-', starting and ending with a letter or digit", name)
	}
	return nil
}
