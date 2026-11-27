package hostreset

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
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
	// The state as the container runtime writes it (builtin/kri/container: json.MarshalIndent of a
	// state whose first field is `json:"id"` kri.ID, then its volumes): kri.ID and kri.Volume have
	// no JSON tags, so their keys are Namespace, Name, UID. A volume's Name comes after the id's.
	b, err := json.MarshalIndent(struct {
		ID      kri.ID       `json:"id"`
		Image   string       `json:"image"`
		Volumes []kri.Volume `json:"volumes"`
	}{kri.ID{Namespace: "dev", Name: "db", UID: "u1"}, "postgres:16", []kri.Volume{{Name: "data", MountPath: "/data"}}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	script := containerStateLines(filepath.Join(root, cloudhypervisor.ContainersDir))
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "container dev/db (from its state; its engine isn't running)" {
		t.Fatalf("not found: %q", out)
	}
	if !strings.Contains(InspectScript, containerStateLines(cloudhypervisor.ContainersDir)) {
		t.Fatal("InspectScript doesn't look at the containers' state")
	}
}

// The same silo, however an inspection found it, is one silo: a reset compares two inspections
// by it (a container read from its engine, then from its state once the plan purged the engine).
func TestSiloIDIgnoresHowTheSiloWasFound(t *testing.T) {
	for line, want := range map[string]string{
		"container dev/db": "container dev/db",
		"container dev/db (from its state; its engine isn't running)": "container dev/db",
		"container dev/db (podman)":                                   "container dev/db",
		"vm kevaso-silo-ab12.service":                                 "vm kevaso-silo-ab12.service",
		"openshell dev/sb":                                            "openshell dev/sb",
	} {
		if got := SiloID(line); got != want {
			t.Errorf("SiloID(%q) = %q, want %q", line, got, want)
		}
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
