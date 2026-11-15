package agent

import (
	"context"
	"testing"
)

// K-038 (the owner's decision: a device outside the plugin's own prefix is refused). kevasod's
// registry now refuses a plugin's AttachVolume answer outside the prefix its manifest declares, and
// a declared prefix is always under /dev/disk/by-id/ (kplugin.DevicePrefixProblem). A device can
// still reach silo status another way (K-037, K-045), so the agent, which formats and mounts it as
// root, must refuse one outside kplugin.ByID too, running nothing: today it accepts any clean
// /dev path, such as the host's own disk. Fix (host lane, internal/agent/volumes.go mount): after
// kplugin.DevicePathProblem, refuse a device that doesn't start with kplugin.ByID (and, where the
// plugin's manifest is on this host, use kplugin.DeviceUnder with its devicePrefixes). Then drop
// the skip (done).
func TestMountRefusesDevicesOutsideByID(t *testing.T) {
	for _, dev := range []string{"/dev/sda1", "/dev/vda", "/dev/nvme0n1p1", "/dev/mapper/root"} {
		h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}}
		a := &Agent{Host: h}
		if err := a.mount(context.Background(), dev, "/var/lib/kevaso/volumes/u/data"); err == nil || err == errNoDevice {
			t.Errorf("%q: %v", dev, err)
		}
		for _, cmd := range []string{"test", "blkid", "mkfs", "mount"} {
			if h.did(cmd) {
				t.Errorf("%q: ran %s: %v", dev, cmd, h.ran)
			}
		}
	}
}
