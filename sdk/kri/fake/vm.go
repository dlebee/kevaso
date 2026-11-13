package fake

import (
	"context"
	"slices"

	"kevaso.com/core/sdk/kri"
)

// VM is the fake as a VM runtime (cloud-hypervisor): volumes fixed while it runs (SetVolumes asks
// for a restart) and mounted by its guest (MountGuestVolumes), which it records.
type VM struct {
	*Runtime
	guest map[kri.ID][]kri.Volume
}

// NewVM returns an empty fake VM runtime.
func NewVM() *VM { return &VM{Runtime: New(), guest: map[kri.ID][]kri.Volume{}} }

func volumesKey(vs []kri.Volume) []kri.Volume {
	out := make([]kri.Volume, len(vs))
	for i, v := range vs {
		out[i] = kri.Volume{Name: v.Name, MountPath: v.MountPath, HostPath: v.HostPath}
	}
	slices.SortFunc(out, func(a, b kri.Volume) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

// SetVolumes implements kri.VolumeSetter.
func (r *VM) SetVolumes(_ context.Context, id kri.ID, vols []kri.Volume) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.get(id)
	if err != nil {
		return false, err
	}
	if slices.Equal(volumesKey(s.spec.Volumes), volumesKey(vols)) {
		return false, nil
	}
	if s.state == kri.Running {
		return true, nil
	}
	r.record("set-volumes", id)
	s.spec.Volumes = append([]kri.Volume(nil), vols...)
	delete(r.guest, id)
	return false, nil
}

// MountGuestVolumes implements kri.GuestVolumes: what the guest mounted is the silo's volumes now.
func (r *VM) MountGuestVolumes(_ context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.get(id)
	if err != nil {
		return err
	}
	if s.state != kri.Running {
		return kri.ErrNotFound
	}
	r.record("mount-guest-volumes", id)
	r.guest[id] = append([]kri.Volume(nil), s.spec.Volumes...)
	return nil
}

// GuestMounts is what the silo's guest last mounted (its shares: volumes with a HostPath).
func (r *VM) GuestMounts(id kri.ID) []kri.Volume {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]kri.Volume(nil), r.guest[id]...)
}

var (
	_ kri.VolumeSetter = (*VM)(nil)
	_ kri.GuestVolumes = (*VM)(nil)
)

// CallLog is Calls, read under the fake's lock (while agents still run).
func (r *VM) CallLog() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.Calls...)
}
