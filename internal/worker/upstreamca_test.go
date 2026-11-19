package worker

import (
	"os"
	"path/filepath"
	"testing"
)

// OpenShell's gateway runs as its own user, so the CA bundle it is given must be readable by
// anyone: a file of public certificates, in a folder others can enter.
func TestOpenShellCABundleIsReadableByTheGatewayUser(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc-kevaso")
	path, err := upstreamCAFile(dir, "", []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, path} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o005 == 0 {
			t.Fatalf("%s is %v: the gateway's user can't read it", p, st.Mode().Perm())
		}
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("bundle written to %s, not %s", path, dir)
	}
	if upstreamCADir == "/var/lib/kevaso" {
		t.Fatal("the bundle must not live in kevasod's root-only data folder")
	}
}
