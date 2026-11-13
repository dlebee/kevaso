//go:build !linux

package ocienv

import "errors"

// inMemory: the runtime is Linux's only; elsewhere nothing is in memory as far as it knows.
func inMemory(string) (bool, string, error) {
	return false, "", errors.New("only on Linux")
}
