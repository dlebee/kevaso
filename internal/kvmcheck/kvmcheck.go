// Package kvmcheck checks that /dev/kvm is usable: it asks the KVM API version and creates (then
// closes) an empty virtual machine. Research E003 / E036 used the same check.
package kvmcheck

import "fmt"

// APIVersion is the only KVM API version Linux has ever reported.
const APIVersion = 12

// Result is what a check found.
type Result struct {
	APIVersion int
	CreatedVM  bool
}

// Verify turns a Result into an error describing what's wrong, or nil when KVM is usable.
func (r Result) Verify() error {
	if r.APIVersion != APIVersion {
		return fmt.Errorf("KVM API version %d, want %d", r.APIVersion, APIVersion)
	}
	if !r.CreatedVM {
		return fmt.Errorf("KVM_CREATE_VM failed")
	}
	return nil
}
