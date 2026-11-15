package hostreset

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
)

// K-078: with Docker installed and stopped, the reset saw no container silo: --force wasn't
// asked, and /var/lib/docker went with every volume. Container silos are found from the
// container runtime's own state on disk too. Run here with a fake root: docker "inactive".
func TestContainerSilosAreFoundWithDockerStopped(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	dir := filepath.Join(root, cloudhypervisor.ContainersDir, "a1b2c3d4e5")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{\n  \"id\": {\n    \"namespace\": \"dev\",\n    \"name\": \"db\",\n    \"uid\": \"u1\"\n  },\n  \"volumes\": [\n    {\n      \"name\": \"data\"\n    }\n  ]\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(containerStateLines, cloudhypervisor.ContainersDir, filepath.Join(root, cloudhypervisor.ContainersDir))
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "container dev/db (from its state; its engine isn't running)") {
		t.Fatalf("not found: %q", out)
	}
	if !strings.Contains(InspectScript, containerStateLines) {
		t.Fatal("InspectScript doesn't look at the containers' state")
	}
}

// K-078: the inspection attaches the storage file read-only to look inside, and must leave the
// host as it found it: a kevasod started after a --dry-run found its pool on a read-only device.
func TestTheInspectionDetachesWhatItAttached(t *testing.T) {
	i, j := strings.Index(InspectScript, "losetup -r -f"), strings.Index(InspectScript, "losetup -d")
	if i < 0 || j < i || !strings.Contains(InspectScript[j-200:j], "vgchange -an") {
		t.Fatalf("attached at %d, detached at %d:\n%s", i, j, InspectScript)
	}
}
