package agent

import (
	"context"
	"testing"
)

// K-038: the agent formats and mounts a volume's device as root. The registry now refuses a
// plugin's device path that isn't a clean device path (kplugin.DevicePathProblem), but a device can
// also reach silo status another way (K-037, K-045), so mount must check it again where it is
// used, and run nothing for one that fails.
func TestMountRefusesWhatIsNoDevicePath(t *testing.T) {
	for _, dev := range []string{"/etc/passwd", "/dev/../etc/shadow", "/dev/fd/3", "/dev/null", "/var/lib/kevaso/volumes/x", "-o", ""} {
		h := &fakeHost{codes: map[string]int{"mountpoint": 1, "blkid": 2}}
		a := &Agent{Host: h}
		err := a.mount(context.Background(), dev, "/var/lib/kevaso/volumes/u/data")
		if err == nil || err == errNoDevice {
			t.Errorf("%q: %v", dev, err)
		}
		for _, cmd := range []string{"test", "blkid", "mkfs", "mount"} {
			if h.did(cmd) {
				t.Errorf("%q: ran %s: %v", dev, cmd, h.ran)
			}
		}
	}
}
