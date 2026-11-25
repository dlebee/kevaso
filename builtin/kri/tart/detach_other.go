//go:build !unix

package tart

import (
	"errors"

	"kevaso.com/core/builtin/kri/hostexec"
)

func detachLocal(hostexec.Cmd, string) error { return errors.New("tart: macOS only") }
