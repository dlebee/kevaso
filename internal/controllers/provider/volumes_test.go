package provider

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Where a mount-reach volume (juicefs) goes: to the silo's host, once the host it was on let go.
func TestPlaceMounted(t *testing.T) {
	silo := func(host, movingFrom string) *v1.Silo {
		s := &v1.Silo{}
		s.Status.Host, s.Status.MovingFrom = host, movingFrom
		return s
	}
	vol := func(at string, mounted bool) v1.VolumeStatus {
		return v1.VolumeStatus{Name: "home", Class: "juicefs", Handle: "volumes/u/home", AttachedTo: at, Mounted: mounted}
	}
	for _, tc := range []struct {
		name   string
		s      *v1.Silo
		vs     v1.VolumeStatus
		lost   bool
		wantAt string
		wait   string
	}{
		{"new: this host", silo("hv1", ""), vol("", false), false, "hv1", ""},
		{"already here", silo("hv1", ""), vol("hv1", true), false, "hv1", ""},
		{"moved, the old host still has it mounted: wait", silo("hv2", "hv1"), vol("hv1", true), false, "hv1", "waiting for hv1 to unmount it"},
		{"moved, the old host let go", silo("hv2", ""), vol("hv1", false), false, "hv2", ""},
		{"old host lost and fenced: go anyway", silo("hv2", ""), vol("hv1", true), true, "hv2", ""},
		{"old host lost but the handoff still waits on it", silo("hv2", "hv1"), vol("hv1", true), true, "hv1", "waiting for hv1 to unmount it"},
		{"the old host has let the silo go and the mount is still recorded", silo("hv2", ""), vol("hv1", true), false, "hv1", "hv1 has let the silo go; its mount is still recorded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs := tc.vs
			vs.Device = "stale"
			got, wait := PlaceMounted(tc.s, vs, tc.s.Status.Host, tc.lost)
			if got.AttachedTo != tc.wantAt || wait != tc.wait || got.Device != "" || got.Handle != tc.vs.Handle {
				t.Fatalf("got %+v %q, want at %s, wait %q", got, wait, tc.wantAt, tc.wait)
			}
			if tc.wait == "" && got.Message != "" {
				t.Fatalf("stale message %q", got.Message)
			}
		})
	}
}

func TestPlaceMountedClearsAStaleUnmountMessage(t *testing.T) {
	s := &v1.Silo{}
	s.Status.Host = "hv2"
	vs := v1.VolumeStatus{Name: "home", Class: "juicefs", Handle: "h", AttachedTo: "hv1", Message: "waiting for hv1 to unmount it"}
	got, wait := PlaceMounted(s, vs, "hv2", false)
	if got.AttachedTo != "hv2" || wait != "" || got.Message != "" {
		t.Fatalf("after the unmount was recorded: %+v %q", got, wait)
	}
}
