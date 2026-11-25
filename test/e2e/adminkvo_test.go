//go:build e2e || metal

package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

// useAdminKvo points kvo at the admin context kvoadm init wrote in the cluster's folder
// (~/.kevaso/clusters/CLUSTER/kvo-admin.yaml): kvo's own context is a plain user, and these tests
// do an admin's work through kvo. It returns the path.
func useAdminKvo(t *testing.T, cluster string) string {
	t.Helper()
	root := os.Getenv("KVOADM_HOME")
	if root == "" {
		root = filepath.Join(os.Getenv("HOME"), ".kevaso")
	}
	p := filepath.Join(root, "clusters", cluster, "kvo-admin.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("kvoadm init wrote no admin kvo config: %v", err)
	}
	t.Setenv("KVO_CONFIG", p)
	return p
}
