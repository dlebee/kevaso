package operators

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyPackage copies the example package to a temp dir, with roles.yaml replaced by roles.
func copyPackage(t *testing.T, roles string) string {
	t.Helper()
	src := "../../examples/operator-session"
	dir := t.TempDir()
	for _, f := range []string{"plugin.yaml", "kinds.yaml", "policies.yaml", "roles.yaml"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if f == "roles.yaml" && roles != "" {
			b = []byte(roles)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// K-054: a package's objects were decoded leniently, so a misspelled field was dropped. Here
// "resourceName" for "resourceNames": the rule silently covered every silo instead of one.
func TestPackageObjectsAreDecodedStrictly(t *testing.T) {
	if _, err := Load(copyPackage(t, "")); err != nil {
		t.Fatalf("the example: %v", err)
	}
	for name, roles := range map[string]string{
		"misspelled rule field": `apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: sessions-controller }
rules:
  - { verbs: [get, delete], resources: [silos], resourceName: [one] }
`,
		"misspelled metadata field": `apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: sessions-controller, namspace: x }
rules:
  - { verbs: [get], resources: [silos] }
`,
		"unknown top-level field": `apiVersion: kevaso/v1
kind: ClusterRole
metadata: { name: sessions-controller }
rule: []
rules:
  - { verbs: [get], resources: [silos] }
`,
	} {
		_, err := Load(copyPackage(t, roles))
		if err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
