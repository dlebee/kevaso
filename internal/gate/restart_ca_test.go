package gate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// kevasod killed while it made the host's egress CA: the file being written is cut short. The
// next start must still have a CA; a cut ca.crt or ca.key failed to parse on every start, and the
// host ran without injection for good.
func TestACAWriteCutShortIsNotKeptAsTheCA(t *testing.T) {
	for _, cut := range []string{"ca.crt", "ca.key"} {
		dir := t.TempDir()
		old := writeFile
		writeFile = func(p string, b []byte, m os.FileMode) error {
			if filepath.Base(p) == cut || filepath.Base(p) == "."+cut+".tmp" {
				_ = os.WriteFile(p, b[:len(b)/2], m) // the kill, halfway
				return errors.New("killed")
			}
			return os.WriteFile(p, b, m)
		}
		_, _ = LoadOrCreateCA(dir, "hv1")
		writeFile = old
		if _, err := LoadOrCreateCA(dir, "hv1"); err != nil {
			t.Fatalf("%s cut short: the next start has no CA: %v", cut, err)
		}
	}
}
