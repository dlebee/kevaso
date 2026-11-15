package kvoadm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// K-038 at install: the device prefix a manifest declares is checked when kvoadm reads it, shown
// to the operator with the side's needs, and the manifest is what kvoadm stores on the host for
// kevasod to check every device answer against.
func TestPluginInstallShowsTheDevicePrefix(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "kevaso-plugin.json")
	_ = os.WriteFile(mf, []byte(`{"name":"linode","devicePrefixes":["/dev/disk/by-id/scsi-0Linode_Volume_"]}`), 0o644)
	o, err := parsePlugin([]string{"root@h", "--name", "linode", "--binary", "b", "--manifest", mf}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := readManifest(&o); err != nil || len(o.DevicePrefixes) != 1 || len(o.ManifestText) == 0 {
		t.Fatalf("%+v %v", o, err)
	}
	var out bytes.Buffer
	if err := grantNeeds(o, nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "volume devices: only under /dev/disk/by-id/scsi-0Linode_Volume_") {
		t.Errorf("not shown the prefix:\n%s", out.String())
	}
	_ = os.WriteFile(mf, []byte(`{"name":"linode","devicePrefixes":["/dev/"]}`), 0o644)
	if err := readManifest(&o); err == nil {
		t.Fatal("a manifest declaring /dev/ as its prefix")
	}
}
