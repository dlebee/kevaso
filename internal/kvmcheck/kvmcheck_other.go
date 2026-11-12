//go:build !linux

package kvmcheck

import "errors"

// Check is only available on Linux.
func Check(string) (Result, error) { return Result{}, errors.New("kvm check: linux only") }
