package boottime

import (
	"time"

	"golang.org/x/sys/unix"
)

// Now is the time since boot, suspend included (CLOCK_BOOTTIME).
func Now() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Since(start) // never on Linux
	}
	return time.Duration(ts.Nano())
}

var start = time.Now()
