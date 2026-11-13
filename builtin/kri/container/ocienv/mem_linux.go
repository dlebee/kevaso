package ocienv

import (
	"fmt"
	"syscall"
)

// inMemory reports whether path is on tmpfs or ramfs (statfs's magic numbers, linux/magic.h).
func inMemory(path string) (bool, string, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false, "", err
	}
	switch uint32(st.Type) {
	case 0x01021994:
		return true, "tmpfs", nil
	case 0x858458f6:
		return true, "ramfs", nil
	}
	return false, fmt.Sprintf("0x%x", uint32(st.Type)), nil
}
