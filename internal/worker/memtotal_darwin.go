//go:build darwin

package worker

import "golang.org/x/sys/unix"

// memTotal on a Mac is hw.memsize: a Mac has no /proc/meminfo, and the 4Gi fallback left a Mac
// worker unable to place a macOS silo (8Gi by default).
func memTotal() int64 {
	if n, err := unix.SysctlUint64("hw.memsize"); err == nil && n > 0 {
		return int64(n)
	}
	return memTotalLinux()
}
