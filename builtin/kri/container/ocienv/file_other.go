//go:build !unix

package ocienv

import (
	"fmt"
	"io/fs"
	"os"
)

// The shim runs only on Linux hosts. This file lets packages that import ocienv (kvoadm) build
// for Windows; there every read of a silo's file is refused.

func openNoFollow(path string) (*os.File, error) {
	return nil, fmt.Errorf("%s: reading a silo's file is not supported on this system", path)
}

func fileOwner(fs.FileInfo) (uid int, nlink uint64, ok bool) { return 0, 0, false }
