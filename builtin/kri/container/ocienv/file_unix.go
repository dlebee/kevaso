//go:build unix

package ocienv

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openNoFollow opens path read-only, refusing a symbolic link.
func openNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a link", path)
		}
		return nil, err
	}
	return f, nil
}

// fileOwner is fi's owner uid and link count. ok is false when the system reports neither.
func fileOwner(fi fs.FileInfo) (uid int, nlink uint64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), uint64(st.Nlink), true //nolint:unconvert // Nlink is uint16 on darwin
}
