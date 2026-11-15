package kplugin

import "testing"

// K-038: the device a plugin answers AttachVolume with is formatted and mounted as root on the
// host. Only a clean path under /dev naming a device may pass on; never a path that leaves /dev,
// a folder of something that is not a block device, or a file descriptor's link.
func TestDevicePaths(t *testing.T) {
	for _, ok := range []string{
		"/dev/disk/by-id/scsi-0Linode_Volume_kvo-a-b-c-0f3a2",
		"/dev/disk/by-id/fake-vol-1",
		"/dev/disk/by-path/pci-0000:00:05.0-scsi-0:0:1:0",
		"/dev/disk/by-uuid/0f3a-11",
		"/dev/vdb", "/dev/sdb", "/dev/nvme1n1", "/dev/mapper/vg-lv", "/dev/xvdf",
	} {
		if err := DevicePathProblem(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "dev/sdb", "/", "/dev", "/dev/",
		"/etc/passwd", "/var/lib/kevaso/volumes/x", "/tmp/disk.img",
		"/dev/../etc/shadow", "/dev/disk/by-id/../../sda1/../../etc", "/dev//sdb", "/dev/sdb/", "/dev/./sdb",
		"/dev/fd/3", "/dev/stdin", "/dev/stdout", "/dev/stderr", // links to the reader's own files
		"/dev/shm/x", "/dev/pts/0", "/dev/mqueue/q", "/dev/hugepages/h", // not block devices
		"/dev/null", "/dev/zero", "/dev/mem", "/dev/kmem", "/dev/port", "/dev/kvm", "/dev/fuse", "/dev/tty", "/dev/console",
		"/dev/sdb -o remount", "/dev/sdb\n", "/dev/sd$b", "/dev/sdb;reboot", "-o /dev/sdb", "/dev/disk/by-id/a b",
	} {
		if err := DevicePathProblem(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
