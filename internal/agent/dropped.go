package agent

import (
	"context"
	"fmt"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// volumesUser is a runtime that says which volumes its copy of a silo uses now (the built-in
// runtimes: what its containers or its VM's layout were made with).
type volumesUser interface {
	VolumesOf(id kri.ID) ([]kri.Volume, bool)
}

// reasonVolumeRemovalWaits: a volume dropped from the spec that the silo's copy still uses.
const reasonVolumeRemovalWaits = "VolumeRemovalWaits"

// releaseDropped lets go of the provider volumes dropped from the silo's spec that are mounted
// here (linode-3.md, core finding 6: one stayed mounted for good, and the control plane waited
// for ever to detach it). A volume change is stop-first: once the silo's copy no longer uses one
// (a VM's SetVolumes after its stop, a container made again by a reset, or no copy at all), it is
// unmounted here and reported unmounted. The control plane detaches it and keeps it until the silo
// is deleted. One the copy still uses (a container's mounts can't change: only a reset makes it
// again) stays mounted, and the silo says why (Updated: VolumeRemovalWaits), never silently.
// The root disk's volume (disk.root) is part of the spec for as long as spec.disk.class names it.
func (a *Agent) releaseDropped(ctx context.Context, rt kri.Runtime, s *v1.Silo, state kri.State) error {
	inSpec := map[string]bool{}
	for _, v := range v1.PluginVolumes(s) { // the root disk's volume counts as wanted
		inSpec[v.Name] = true
	}
	var dropped []v1.VolumeStatus
	for _, vs := range s.Status.Volumes {
		if inSpec[vs.Name] || vs.AttachedTo != a.HostName {
			continue
		}
		_, remembered := a.nodeMounts.Load(a.nodeMount(s.UID, vs).Path)
		if vs.Mounted || remembered {
			dropped = append(dropped, vs)
		}
	}
	waits := meta.FindCondition(s.Status.Conditions, "Updated")
	if len(dropped) == 0 {
		if waits != nil && waits.Reason == reasonVolumeRemovalWaits {
			return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				setCond(st, "Updated", meta.ConditionTrue, "VolumesRemoved", "the volumes removed from its spec are let go here", s.Generation, a.now())
			})
		}
		return nil
	}
	used, known := map[string]bool{}, state == kri.Absent
	if !known {
		if vu, ok := rt.(volumesUser); ok {
			if vols, ok := vu.VolumesOf(idOf(s)); ok {
				known = true
				for _, v := range vols {
					used[v.Name] = true
				}
			}
		}
	}
	var still []string
	for _, vs := range dropped {
		if !known || used[vs.Name] {
			still = append(still, vs.Name)
			continue
		}
		if err := a.unmountOne(ctx, s.UID, vs); err != nil {
			return err
		}
		name := vs.Name
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			for i := range st.Volumes {
				if st.Volumes[i].Name == name && st.Volumes[i].AttachedTo == a.HostName {
					st.Volumes[i].Mounted = false
				}
			}
		}); err != nil {
			return err
		}
		a.log("silo %s/%s: volume %s was removed from its spec: unmounted here; it stays until the silo is deleted", s.Namespace, s.Name, vs.Name)
	}
	if len(still) == 0 {
		return nil
	}
	msg := fmt.Sprintf("volume(s) %s removed from its spec: runtime %s changes a silo's volumes only when its copy is made again; they stay mounted and attached here until its next reset (kvo reset)",
		strings.Join(still, ", "), s.Spec.Runtime)
	if waits != nil && waits.Reason == reasonVolumeRemovalWaits && waits.Message == msg {
		return nil
	}
	a.log("silo %s/%s: %s", s.Namespace, s.Name, msg)
	return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		setCond(st, "Updated", meta.ConditionFalse, reasonVolumeRemovalWaits, msg, s.Generation, a.now())
	})
}

// unmountOne unmounts one volume of a silo here: through the plugin's node side that mounted it,
// or the host's own mount at its folder (the folder removed once empty, never recursively).
func (a *Agent) unmountOne(ctx context.Context, uid string, vs v1.VolumeStatus) error {
	if n, ok := a.nodeFor(vs.Class); ok {
		m := a.nodeMount(uid, vs)
		if err := n.UnmountVolume(ctx, m); err != nil {
			return fmt.Errorf("volume %s: %w", vs.Name, err)
		}
		a.nodeMounts.Delete(m.Path)
		return nil
	}
	if a.Host == nil {
		return nil
	}
	dir := a.VolumePath(uid, vs.Name)
	switch _, code, err := a.run(ctx, "mountpoint", "-q", dir); code {
	case 0:
		if _, _, err := a.run(ctx, "umount", dir); err != nil {
			return err
		}
		if a.mountedAt(ctx, dir) {
			return fmt.Errorf("%s is still mounted after umount (will try again)", dir)
		}
	case notAMountPoint:
	default:
		return fmt.Errorf("can't tell whether %s is mounted (%v) (will try again)", dir, err)
	}
	_, _, _ = a.run(ctx, "rmdir", dir) // empty once unmounted; one that isn't stays
	return nil
}
