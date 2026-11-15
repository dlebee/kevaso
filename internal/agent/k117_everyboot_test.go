package agent_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/sdk/kri"
)

// K-117: init steps that run at every boot run again after a crash restart (the Failed branch),
// as after any other start: through Exec for a VM, as init containers before the main process for
// a container runtime.
func TestEveryBootStepsRunAgainAfterACrashRestart(t *testing.T) {
	for _, vm := range []bool{true, false} {
		t.Run(map[bool]string{true: "vm", false: "container"}[vm], func(t *testing.T) {
			w := newTwice(t, vm)
			var execs atomic.Int32
			h := w.d.Handler
			w.d.Handler = func(id kri.ID, cmd []string, in []byte) (string, int) {
				if strings.Contains(strings.Join(cmd, " "), bootStep) {
					execs.Add(1)
				}
				return h(id, cmd, in)
			}
			runs := func() int {
				if vm {
					return int(execs.Load())
				}
				n := 0
				for _, c := range w.d.CallLog() {
					if strings.HasPrefix(c, "init boot ") {
						n++
					}
				}
				return n
			}
			w.until("the silo is reported Running", 100*time.Millisecond, w.runningReported)
			if n := runs(); n != 1 {
				t.Fatalf("the boot step ran %d times at the first start", n)
			}
			w.d.kill(w.id)
			w.until("restarted after the crash and reported Running", 100*time.Millisecond, func() bool {
				r := w.get().Status.Restarts
				return r != nil && r.Count == 1 && w.runningReported()
			})
			if n := runs(); n != 2 {
				t.Fatalf("the boot step ran %d times in all after a crash restart, want 2", n)
			}
		})
	}
}
