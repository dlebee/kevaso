package kplugin

import (
	"strings"
	"testing"
)

// K-038 (the owner's decision): a device a plugin answers must be under the prefix its manifest
// declares (devicePrefixes), checked when the manifest is read at install and on every answer.
// A prefix is a stable name's start under /dev/disk/by-id/; never /dev itself, by-id as a whole,
// or an unstable kernel name.
func TestDevicePrefixes(t *testing.T) {
	for _, ok := range []string{"/dev/disk/by-id/scsi-0Linode_Volume_", "/dev/disk/by-id/virtio-kvo"} {
		if err := DevicePrefixProblem(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/dev/", "/dev/sd", "/dev/disk/by-id/", "/dev/disk/by-id", "/dev/disk/by-path/pci-",
		"/dev/disk/by-id/../", "/dev/disk/by-id/a/b", "/dev/disk/by-id/a b", "/etc/"} {
		if err := DevicePrefixProblem(bad); err == nil {
			t.Errorf("prefix %q accepted", bad)
		}
	}
	m, err := ParseManifest([]byte(`{"name":"linode","devicePrefixes":["/dev/disk/by-id/scsi-0Linode_Volume_"]}`))
	if err != nil || len(m.DevicePrefixes) != 1 {
		t.Fatalf("a manifest declaring its prefix: %+v %v", m, err)
	}
	if _, err := ParseManifest([]byte(`{"name":"linode","devicePrefixes":["/dev/sd"]}`)); err == nil || !strings.Contains(err.Error(), "/dev/disk/by-id/") {
		t.Fatalf("a manifest declaring /dev/sd: %v", err)
	}
	prefixes := []string{"/dev/disk/by-id/scsi-0Linode_Volume_"}
	if err := DeviceUnder("/dev/disk/by-id/scsi-0Linode_Volume_kvo-a-1", prefixes); err != nil {
		t.Fatalf("its own device: %v", err)
	}
	for _, bad := range []string{"/dev/sda1", "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0", "/dev/disk/by-id/scsi-0Linode_Volume_",
		"/dev/disk/by-id/scsi-0Linode_Volume_x/../../../sda1", "/dev/disk/by-id/scsi-0Linode_Volume_x/y"} {
		if err := DeviceUnder(bad, prefixes); err == nil {
			t.Errorf("%s accepted under %v", bad, prefixes)
		}
	}
	if err := DeviceUnder("/dev/disk/by-id/scsi-0Linode_Volume_x", nil); err == nil || !strings.Contains(err.Error(), "devicePrefixes") {
		t.Fatalf("no prefix declared: %v", err)
	}
}
