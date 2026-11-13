package mesh

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// kevasod killed while it made a mesh key: the key file is cut short (or empty). The next start
// must still get a key; a cut one failed to parse on every start, Run returned, and the host stayed
// off the mesh for good (still Ready).
func TestAMeshKeyWriteCutShortIsNotKept(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kevaso0.key")
	old := writeFile
	writeFile = func(name string, b []byte, m os.FileMode) error {
		_ = os.WriteFile(name, b[:len(b)/3], m) // the kill
		return errors.New("killed")
	}
	_, _ = LoadKey(p)
	writeFile = old
	if _, err := LoadKey(p); err != nil {
		t.Fatalf("the next start has no key: %v", err)
	}
}
