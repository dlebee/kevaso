package agent

import (
	"testing"
	"time"

	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
)

// K-072: the agent's fence counts silence on the boot clock. A wall clock stepped back (a time
// server reached while the control plane isn't) must not make a silence shorter than it is.
func TestSilenceIsCountedOnTheBootClock(t *testing.T) {
	contactBoot := boottime.Now() - 3*time.Minute // the last heartbeat, 3 minutes ago
	a := &Agent{Clock: clock.Real{},
		LastContact:     func() time.Time { return time.Now() }, // wall: "just now", stepped
		LastContactBoot: func() (time.Duration, bool) { return contactBoot, true }}
	a.started, a.startedBoot = time.Now(), boottime.Now()
	if got := a.silence(); got < 3*time.Minute || got > 3*time.Minute+time.Second {
		t.Fatalf("silence %s, want 3m (the boot clock's), not the wall clock's", got)
	}
}
