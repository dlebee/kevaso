// Package boottime is the clock the fence counts silence on (K-072): time since boot, suspend
// included, never stepped (CLOCK_BOOTTIME on Linux), and the boot it belongs to. The wall clock
// can be stepped back or forward by a time server while the control plane is away; a silence
// counted on it can end late, past the control plane's margin. Readings from two processes of
// one boot compare; readings of different boots don't.
package boottime

import (
	"os"
	"strings"
	"sync"
	"time"
)

// ID is this boot's id (/proc/sys/kernel/random/boot_id): "" where there is none (not Linux).
func ID() string {
	bootOnce.Do(func() {
		if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
			bootID = strings.TrimSpace(string(b))
		}
	})
	return bootID
}

var (
	bootOnce sync.Once
	bootID   string
)

// Since is how long since a reading of Now, in this boot.
func Since(reading time.Duration) time.Duration { return Now() - reading }
