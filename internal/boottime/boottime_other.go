//go:build !linux

package boottime

import "time"

// Now is, where there's no boot clock to share (tests on a Mac), monotonic time since this
// process started: comparable within the process only (ID is "" there, so nothing compares it
// across processes).
func Now() time.Duration { return time.Since(start) }

var start = time.Now()
