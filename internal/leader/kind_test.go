package leader

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// The leader's lease lives in the store beside API objects: its kind must never be an API kind,
// or listing that kind would meet an object that isn't one (it once shared "Lease" with port leases).
func TestKindIsNotAnAPIKind(t *testing.T) {
	if _, ok := v1.Lookup(Kind); ok {
		t.Fatalf("store kind %q is also an API kind", Kind)
	}
}
