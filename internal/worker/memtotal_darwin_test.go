//go:build darwin

package worker

import (
	"testing"

	"golang.org/x/sys/unix"
)

// A Mac worker reports its real memory, not the 4Gi fallback.
func TestMemTotalOnAMacIsHwMemsize(t *testing.T) {
	want, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		t.Skip(err)
	}
	if got := memTotal(); got != int64(want) {
		t.Fatalf("memTotal = %d, hw.memsize = %d", got, want)
	}
}
