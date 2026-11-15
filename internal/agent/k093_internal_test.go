package agent

import (
	"testing"
	"time"

	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
)

// K-093: on a host that is itself a VM, the silence is counted on either clock, whichever says
// more: a VM paused by its hypervisor may not count the pause on its boot clock, and its opted-in
// silos ran on beside the copy the control plane started elsewhere. Bare metal counts on the boot
// clock alone, as before (K-072: a time server stepping the wall clock stops nothing).
func TestAHostThatIsAVMCountsSilenceOnEitherClock(t *testing.T) {
	for _, vm := range []bool{true, false} {
		clk := clock.NewFake(time.Unix(1_000_000, 0))
		contact := clk.Now()
		a := &Agent{Clock: clk, HostIsVM: func() bool { return vm },
			LastContact:     func() time.Time { return contact },
			LastContactBoot: func() (time.Duration, bool) { return boottime.Now(), true }, // the boot clock saw none of the pause
		}
		a.started = clk.Now()
		clk.Step(10 * time.Minute) // the pause: the wall clock moved, the boot clock didn't
		got := a.silence()
		if vm && got < 10*time.Minute {
			t.Errorf("a VM after a 10-minute pause counts %s of silence: its silos would run on", got)
		}
		if !vm && got > time.Minute {
			t.Errorf("bare metal counts %s on the wall clock: a time step would stop its silos", got)
		}
	}
}
