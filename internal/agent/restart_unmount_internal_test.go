package agent

import (
	"context"
	"os"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/hostexec"
)

// stuckMount is a host where a volume folder stays mounted after one umount (two mounts stacked
// on it: a node side that mounted again after a restart, say).
type stuckMount struct{ removed []string }

func (h *stuckMount) Run(_ context.Context, c hostexec.Cmd) (int, error) {
	if c.Name == "mountpoint" {
		return 0, nil // still mounted, every time
	}
	return 0, nil
}
func (h *stuckMount) WriteFile(string, []byte, os.FileMode) error { return nil }
func (h *stuckMount) ReadFile(string) ([]byte, error)             { return nil, os.ErrNotExist }
func (h *stuckMount) RemoveAll(p string) error                    { h.removed = append(h.removed, p); return nil }
func (h *stuckMount) Glob(p string) ([]string, error) {
	return []string{strings.TrimSuffix(p, "*") + "data"}, nil
}

// The silo's volume folder is removed recursively once unmounted. If it's still mounted after
// the umount, removing it deletes the volume's files: it must be left, and the unmount retried.
func TestUnmountNeverRemovesAFolderThatIsStillMounted(t *testing.T) {
	h := &stuckMount{}
	a := &Agent{Host: h}
	if err := a.unmountDirs(context.Background(), "u1"); err == nil {
		t.Fatal("no error for a folder still mounted")
	}
	if len(h.removed) > 0 {
		t.Fatalf("removed %v while still mounted: the volume's files went with it", h.removed)
	}
}
