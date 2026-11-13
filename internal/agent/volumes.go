package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/sdk/kplugin"
	"kevaso.com/core/sdk/kri"
)

// DefaultVolumesDir is where provider volumes are mounted: DIR/SILO-UID/VOLUME.
const DefaultVolumesDir = "/var/lib/kevaso/volumes"

func (a *Agent) volumesDir() string {
	if a.VolumesDir != "" {
		return a.VolumesDir
	}
	return DefaultVolumesDir
}

// VolumePath is where a silo's provider volume is mounted on its host.
func (a *Agent) VolumePath(uid, name string) string { return path.Join(a.volumesDir(), uid, name) }

func (a *Agent) run(ctx context.Context, name string, args ...string) (string, int, error) {
	var out, errb bytes.Buffer
	code, err := a.Host.Run(ctx, hostexec.Cmd{Name: name, Args: args, Stdout: &out, Stderr: &errb})
	if err != nil {
		return "", code, fmt.Errorf("%s: %w", name, err)
	}
	if code != 0 {
		return out.String(), code, fmt.Errorf("%s %s: exit %d: %s", name, strings.Join(args, " "), code, strings.TrimSpace(errb.String()))
	}
	return out.String(), 0, nil
}

// nodeFor is the plugin node side on this host that mounts a storage class (reach mount).
func (a *Agent) nodeFor(class string) (kplugin.Node, bool) {
	if a.Nodes == nil {
		return nil, false
	}
	p, c, ok := a.Nodes.Storage(class)
	if !ok || !c.Mounted() {
		return nil, false
	}
	return p.Conn, true
}

// nodeMount is what the node side is asked to mount, or unmount, for a silo's volume.
func (a *Agent) nodeMount(uid string, vs v1.VolumeStatus) kplugin.NodeMount {
	return kplugin.NodeMount{Class: vs.Class, Handle: vs.Handle, ID: uid + "/" + vs.Name, Path: a.VolumePath(uid, vs.Name)}
}

// mountVolumes makes the silo's provider volumes ready on this host: attached (the control plane
// does that), formatted once, mounted; or, for a mount-reach class, mounted by the plugin's node
// side here. ready is false while one isn't there yet (msg says which).
func (a *Agent) mountVolumes(ctx context.Context, s *v1.Silo) (vols []kri.Volume, ready bool, msg string, err error) {
	byName := map[string]v1.VolumeStatus{}
	for _, vs := range s.Status.Volumes {
		byName[vs.Name] = vs
	}
	for _, v := range s.Spec.Volumes {
		size, _ := v1.ParseBytes(v.Size)
		kv := kri.Volume{Name: v.Name, MountPath: v.MountPath, SizeBytes: size}
		if v.Class == "" || v.Class == v1.VolumeLocal {
			vols = append(vols, kv)
			continue
		}
		vs, ok := byName[v.Name]
		if n, mounts := a.nodeFor(v.Class); mounts {
			dir, ready, msg, err := a.mountByNode(ctx, s, n, vs, ok)
			if !ready || err != nil {
				return nil, false, msg, err
			}
			kv.HostPath = dir
			vols = append(vols, kv)
			continue
		}
		switch {
		case ok && vs.AttachedTo == a.HostName && vs.Handle != "" && vs.Device == "":
			// The control plane says it's here, with nothing attached: a mount class.
			return nil, false, "no plugin on " + a.HostName + " mounts storage class " + v.Class + " (is its node side running?)", nil
		case a.Host == nil:
			return nil, false, "this host can't mount provider volumes", nil
		case !ok || vs.AttachedTo != a.HostName || vs.Device == "":
			m := "waiting for volume " + v.Name + " to be attached"
			if ok && vs.Message != "" {
				m += " (" + vs.Message + ")"
			}
			return nil, false, m, nil
		}
		dir := a.VolumePath(s.UID, v.Name)
		if err := a.mount(ctx, vs.Device, dir); err != nil {
			if err == errNoDevice {
				return nil, false, "waiting for " + vs.Device + " to appear", nil
			}
			return nil, false, "", fmt.Errorf("volume %s: %w", v.Name, err)
		}
		kv.HostPath = dir
		vols = append(vols, kv)
		if !vs.Mounted {
			name := v.Name
			if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				for i := range st.Volumes {
					if st.Volumes[i].Name == name {
						st.Volumes[i].Mounted = true
					}
				}
			}); err != nil {
				return nil, false, "", err
			}
		}
	}
	return vols, true, "", nil
}

// mountByNode has the plugin's node side mount a mount-reach volume at the silo's volume path,
// once the control plane says it's this host's (the old host let go), and records it's mounted.
func (a *Agent) mountByNode(ctx context.Context, s *v1.Silo, n kplugin.Node, vs v1.VolumeStatus, known bool) (string, bool, string, error) {
	if !known || vs.Handle == "" || vs.AttachedTo != a.HostName {
		m := "waiting for volume " + vs.Name + " to be ready for " + a.HostName
		if !known {
			m = "waiting for the volume to be created"
		} else if vs.Message != "" {
			m += " (" + vs.Message + ")"
		}
		return "", false, m, nil
	}
	m := a.nodeMount(s.UID, vs)
	if done, _ := a.nodeMounts.Load(m.Path); done != m.Handle || !vs.Mounted {
		err := n.MountVolume(ctx, m)
		if errors.Is(err, kplugin.ErrInProgress) {
			return "", false, "mounting volume " + vs.Name + ": " + err.Error(), nil
		}
		if err != nil {
			return "", false, "", fmt.Errorf("volume %s: %w", vs.Name, err)
		}
		a.nodeMounts.Store(m.Path, m.Handle)
	}
	if !vs.Mounted {
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			for i := range st.Volumes {
				if st.Volumes[i].Name == vs.Name {
					st.Volumes[i].Mounted = true
				}
			}
		}); err != nil {
			return "", false, "", err
		}
	}
	return m.Path, true, "", nil
}

var errNoDevice = fmt.Errorf("device not there yet")

// mount mounts dev at dir, formatting it first only if it holds no filesystem at all: a volume
// that comes back (another host, a restart) is never wiped.
func (a *Agent) mount(ctx context.Context, dev, dir string) error {
	if _, code, _ := a.run(ctx, "mountpoint", "-q", dir); code == 0 {
		return nil
	}
	if _, _, err := a.run(ctx, "test", "-b", dev); err != nil {
		return errNoDevice
	}
	out, code, err := a.run(ctx, "blkid", "-p", "-o", "value", "-s", "TYPE", dev)
	switch {
	case code == 2: // nothing on it: a new volume
		if _, _, err := a.run(ctx, "mkfs.ext4", "-q", "-m", "0", dev); err != nil {
			return err
		}
		a.log("formatted %s (ext4): it was empty", dev)
	case err != nil:
		return fmt.Errorf("probing %s (not formatting it): %w", dev, err)
	case strings.TrimSpace(out) == "":
		return fmt.Errorf("%s has something on it blkid can't name: not formatting it", dev)
	}
	if _, _, err := a.run(ctx, "mkdir", "-p", dir); err != nil {
		return err
	}
	_, _, err = a.run(ctx, "mount", "-o", "noatime", dev, dir)
	return err
}

// unmountVolumes unmounts what this host mounted for a silo (by UID), and says so on the silo if
// it's still in the API, so the control plane can detach the volumes. Mount-reach volumes are
// unmounted by the plugin's node side that mounted them.
func (a *Agent) unmountVolumes(ctx context.Context, uid string, s *v1.Silo) error {
	if s != nil && s.UID == uid {
		for _, vs := range s.Status.Volumes {
			m := a.nodeMount(uid, vs)
			_, remembered := a.nodeMounts.Load(m.Path)
			if vs.AttachedTo != a.HostName || (!vs.Mounted && !remembered) {
				continue
			}
			n, ok := a.nodeFor(vs.Class)
			if !ok {
				continue
			}
			if err := n.UnmountVolume(ctx, m); err != nil {
				return fmt.Errorf("volume %s: %w", vs.Name, err)
			}
			a.nodeMounts.Delete(m.Path)
			a.log("unmounted %s (%s)", m.Path, vs.Class)
		}
	}
	if a.Host != nil {
		if err := a.unmountDirs(ctx, uid); err != nil {
			return err
		}
	}
	if s == nil || s.UID != uid {
		return nil
	}
	if _, moving := moves.Released(s.Status, a.HostName); moving {
		return nil // moving away: the release says they're unmounted, in the one write it may make
	}
	mine := false
	for _, vs := range s.Status.Volumes {
		mine = mine || (vs.Mounted && vs.AttachedTo == a.HostName)
	}
	if !mine {
		return nil
	}
	return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		for i := range st.Volumes {
			if st.Volumes[i].AttachedTo == a.HostName {
				st.Volumes[i].Mounted = false
			}
		}
	})
}

// unmountDirs unmounts whatever is still mounted under the silo's volume folder, and removes it.
func (a *Agent) unmountDirs(ctx context.Context, uid string) error {
	dirs, _ := a.Host.Glob(path.Join(a.volumesDir(), uid, "*"))
	for _, d := range dirs {
		if _, code, _ := a.run(ctx, "mountpoint", "-q", d); code == 0 {
			if _, _, err := a.run(ctx, "umount", d); err != nil {
				return err
			}
			a.log("unmounted %s", d)
		}
	}
	if len(dirs) > 0 {
		return a.Host.RemoveAll(path.Join(a.volumesDir(), uid))
	}
	return nil
}

// volumeWait is how soon to look again while a volume isn't there yet.
const volumeWait = 3 * time.Second
