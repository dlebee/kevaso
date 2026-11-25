package hostexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLookPathUsesTheHostPathNotKevasods(t *testing.T) {
	if got := LookPath("/bin/sh"); got != "/bin/sh" {
		t.Fatal(got)
	}
	if got := LookPath("definitely-not-installed-xyz"); got != "definitely-not-installed-xyz" {
		t.Fatalf("a missing program keeps its name so exec reports it: %q", got)
	}
	t.Setenv("PATH", t.TempDir()) // kevasod's own PATH knows nothing
	sh := LookPath("sh")
	if !filepath.IsAbs(sh) {
		t.Fatalf("sh not found in the host path: %q", sh)
	}
	if fi, err := os.Stat(sh); err != nil || fi.IsDir() {
		t.Fatal(sh)
	}
}
