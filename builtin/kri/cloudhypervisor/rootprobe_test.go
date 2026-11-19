package cloudhypervisor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A failed probe of a moved root disk (the command cannot be run, or test -e exits
// with anything but 1) is not "no disk yet": nothing is written over the file.
func TestAFailedRootDiskProbeWritesNothing(t *testing.T) {
	ctx := context.Background()
	dir := "/var/lib/kevaso/volumes/uid-web/disk.root"
	file := dir + "/" + RootImage
	for _, bad := range []error{errors.New("exit 2"), errors.New("fork/exec test: no such file")} {
		h := newFakeHost()
		r := newRuntime(t, h)
		h.answer = func(cmd string) (string, error) {
			switch {
			case cmd == "test -e "+file:
				return "", bad
			case strings.HasPrefix(cmd, "systemctl is-active"):
				return "inactive", errors.New("exit 3")
			}
			return "", nil
		}
		sp := spec("web")
		sp.DiskHostPath = dir
		err := r.Create(ctx, sp)
		if err == nil || !strings.Contains(err.Error(), "not writing it") {
			t.Fatalf("probe %v: %v", bad, err)
		}
		cmds := strings.Join(h.commands(), "\n")
		if strings.Contains(cmds, "qemu-img") || strings.Contains(cmds, "mv -f") {
			t.Fatalf("probe %v wrote a disk:\n%s", bad, cmds)
		}
	}
}
