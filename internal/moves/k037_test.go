package moves

import (
	"errors"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-037: a volume's status is the control plane's but for mounted, which is its host's. A host
// that rewrites a handle, class, region, device, size or message points the control plane's next
// attach, detach or delete at another volume (or the agent's mkfs and mount at another disk), so
// HostWrite refuses any change but mounted.
func TestK037AHostWritesOnlyMountedOfAVolume(t *testing.T) {
	vol := v1.VolumeStatus{Name: "data", Class: "linode-block", Handle: "vol-1", Region: "ca-central", AttachedTo: "hv2",
		Device: "/dev/disk/by-id/scsi-0Linode_Volume_kvo-1", SizeBytes: 10 << 30, Message: "attached"}
	old := v1.SiloStatus{Host: "hv2", Phase: "Running", Volumes: []v1.VolumeStatus{vol}}
	for _, tc := range []struct {
		name string
		f    func(*v1.VolumeStatus)
		ok   bool
	}{
		{"mounted", func(v *v1.VolumeStatus) { v.Mounted = true }, true},
		{"nothing", func(*v1.VolumeStatus) {}, true},
		{"handle", func(v *v1.VolumeStatus) { v.Handle = "vol-999" }, false},
		{"class", func(v *v1.VolumeStatus) { v.Class = "juicefs" }, false},
		{"region", func(v *v1.VolumeStatus) { v.Region = "us-east" }, false},
		{"device", func(v *v1.VolumeStatus) { v.Device = "/dev/sda1" }, false},
		{"size", func(v *v1.VolumeStatus) { v.SizeBytes = 1 }, false},
		{"size not enforced", func(v *v1.VolumeStatus) { v.SizeNotEnforced = true }, false},
		{"message", func(v *v1.VolumeStatus) { v.Message = "all fine, detach me" }, false},
	} {
		next := old
		next.Volumes = []v1.VolumeStatus{vol}
		tc.f(&next.Volumes[0])
		err := HostWrite(old, next, "hv2")
		if (err == nil) != tc.ok {
			t.Errorf("%s: HostWrite = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrHostWrite) {
			t.Errorf("%s: %v is not ErrHostWrite", tc.name, err)
		}
	}
}
