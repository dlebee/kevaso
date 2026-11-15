package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
)

// volumeHost answers mountpoint with a given exit code (or a failure to run it) and records the
// rest.
type volumeHost struct {
	mountpoint int
	runErr     error
	cmds       []string
	removed    []string
}

func (h *volumeHost) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	h.cmds = append(h.cmds, c.Name+" "+strings.Join(c.Args, " "))
	if c.Name == "mountpoint" {
		return h.mountpoint, h.runErr
	}
	return 0, nil
}
func (h *volumeHost) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *volumeHost) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (h *volumeHost) RemoveAll(p string) error                    { h.removed = append(h.removed, p); return nil }
func (h *volumeHost) Glob(p string) ([]string, error) {
	return []string{strings.TrimSuffix(p, "*") + "data"}, nil
}

// K-006: after a failed "is it mounted?" check the silo's volume folder was removed recursively,
// the mounted volume's files with it.
func TestAFailedMountCheckRemovesNothing(t *testing.T) {
	for _, h := range []*volumeHost{{mountpoint: -1, runErr: errors.New("signal: killed")}, {mountpoint: 1}} {
		a := &Agent{Host: h}
		if err := a.unmountDirs(context.Background(), "u1"); err == nil {
			t.Errorf("mountpoint %d %v: no error", h.mountpoint, h.runErr)
		}
		for _, c := range h.cmds {
			if strings.HasPrefix(c, "rmdir") || strings.HasPrefix(c, "rm ") {
				t.Errorf("mountpoint %d: removed something: %v", h.mountpoint, h.cmds)
			}
		}
		if len(h.removed) > 0 {
			t.Errorf("mountpoint %d: removed %v recursively", h.mountpoint, h.removed)
		}
	}
}

// Not a mount point: only the empty folders go (rmdir), never a recursive remove.
func TestUnmountedFoldersAreRemovedOnlyIfEmpty(t *testing.T) {
	h := &volumeHost{mountpoint: notAMountPoint}
	a := &Agent{Host: h}
	if err := a.unmountDirs(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if len(h.removed) > 0 {
		t.Fatalf("removed recursively: %v", h.removed)
	}
	want := []string{"rmdir " + a.volumesDir() + "/u1/data", "rmdir " + a.volumesDir() + "/u1"}
	got := h.cmds[len(h.cmds)-2:]
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("removal: %v, want %v", got, want)
	}
}
