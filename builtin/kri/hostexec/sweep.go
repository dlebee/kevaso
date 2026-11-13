package hostexec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"

	"kevaso.com/core/sdk/kri"
)

// NewMarker returns a value for kri.ExecMarkerEnv, unique to one Exec.
func NewMarker() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// MarkedPIDs finds the processes on this host whose environment holds marker: what one Exec
// started inside a container (the host sees every container's processes in /proc).
func MarkedPIDs(r Runner, marker string) []int {
	want := []byte(kri.ExecMarkerEnv + "=" + marker)
	files, _ := r.Glob("/proc/[0-9]*/environ")
	var pids []int
	for _, f := range files {
		b, err := r.ReadFile(f)
		if err != nil {
			continue // gone already, or not ours to read
		}
		for v := range bytes.SplitSeq(b, []byte{0}) {
			if bytes.Equal(v, want) {
				p, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(f, "/proc/"), "/environ"))
				if err == nil && p > 1 {
					pids = append(pids, p)
				}
				break
			}
		}
	}
	return pids
}

// KillMarked kills (SIGKILL) every process MarkedPIDs finds, and returns how many it found.
func KillMarked(ctx context.Context, r Runner, marker string) int {
	pids := MarkedPIDs(r, marker)
	if len(pids) == 0 {
		return 0
	}
	args := []string{"-KILL"}
	for _, p := range pids {
		args = append(args, strconv.Itoa(p))
	}
	_, _ = r.Run(ctx, Cmd{Name: "kill", Args: args})
	return len(pids)
}

// SweepScript is the same sweep run inside a silo with sh (for runtimes whose host doesn't see the
// silo's processes: a VM, an OpenShell sandbox): `sh -c SweepScript sh MARKER`. It needs only sh,
// tr, grep and kill, which every Linux image with a shell has.
const SweepScript = `for f in /proc/[0-9]*/environ; do p=${f#/proc/}; p=${p%/environ}; ` +
	`[ "$p" = "$$" ] && continue; ` +
	`if tr '\000' '\n' < "$f" 2>/dev/null | grep -qx "` + kri.ExecMarkerEnv + `=$1"; then kill -KILL "$p" 2>/dev/null; fi; done; true`
