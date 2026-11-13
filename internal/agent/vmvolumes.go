package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// mountRootDisk has the plugin's node side mount the volume that keeps a VM silo's own disk
// (spec.disk.class on a mount class), like any mount-reach volume, and returns its folder for the
// runtime ("" for a local disk). ready is false while it isn't this host's yet.
func (a *Agent) mountRootDisk(ctx context.Context, s *v1.Silo) (string, bool, string, error) {
	d, ok := v1.DiskVolume(s)
	if !ok {
		return "", true, "", nil
	}
	n, mounts := a.nodeFor(d.Class)
	if !mounts {
		return "", false, "no plugin on " + a.HostName + " mounts storage class " + d.Class + " (the silo's disk is on it; is its node side running?)", nil
	}
	var vs v1.VolumeStatus
	known := false
	for _, x := range s.Status.Volumes {
		if x.Name == d.Name {
			vs, known = x, true
		}
	}
	if !known {
		vs.Name = d.Name
	}
	return a.mountByNode(ctx, s, n, vs, known)
}

// setVolumes gives a runtime whose volumes are fixed while the silo runs (a VM) the volumes it
// should have; a running silo with others is stopped for them (no hot-add: a volume change
// restarts it). restart says it was stopped.
func (a *Agent) setVolumes(ctx context.Context, rt kri.Runtime, s *v1.Silo, state kri.State, vols []kri.Volume) (bool, error) {
	vs, ok := rt.(kri.VolumeSetter)
	if !ok || state == kri.Absent {
		return false, nil
	}
	restart, err := vs.SetVolumes(ctx, idOf(s), vols)
	if err != nil || !restart {
		return false, err
	}
	if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Phase = PhaseStarting
		setCond(st, "Ready", meta.ConditionFalse, "VolumesChanged", "restarting for its new volumes", s.Generation, a.now())
	}); err != nil {
		return true, err
	}
	a.log("silo %s/%s: volumes changed, restarting it", s.Namespace, s.Name)
	if err := rt.Stop(ctx, idOf(s)); err != nil {
		return true, fmt.Errorf("stop for new volumes: %w", err)
	}
	a.guestMounted.Delete(s.UID)
	return true, nil
}

// guestKey identifies a silo's volumes as its guest mounts them.
func guestKey(vols []kri.Volume) string {
	parts := make([]string, 0, len(vols))
	for _, v := range vols {
		parts = append(parts, v.Name+"="+v.MountPath+"@"+v.HostPath)
	}
	slices.Sort(parts)
	return strings.Join(parts, "\n")
}

// mountGuestVolumes has a VM's guest mount its volumes (once per agent run and volume set; the
// guest mounts them itself at later boots).
func (a *Agent) mountGuestVolumes(ctx context.Context, rt kri.Runtime, s *v1.Silo, vols []kri.Volume) error {
	gv, ok := rt.(kri.GuestVolumes)
	if !ok || len(vols) == 0 {
		return nil
	}
	key := guestKey(vols)
	if k, ok := a.guestMounted.Load(s.UID); ok && k == key {
		return nil
	}
	if err := gv.MountGuestVolumes(ctx, idOf(s)); err != nil {
		return fmt.Errorf("mounting volumes in the guest: %w", err)
	}
	a.guestMounted.Store(s.UID, key)
	return nil
}
