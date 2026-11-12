package agent

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
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

// mountVolumes makes the silo's provider volumes ready on this host: attached (the control plane
// does that), formatted once, mounted. ready is false while one isn't there yet (msg says which).
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
		switch {
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
// it's still in the API, so the control plane can detach the volumes.
func (a *Agent) unmountVolumes(ctx context.Context, uid string, s *v1.Silo) error {
	if a.Host == nil {
		return nil
	}
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
		if err := a.Host.RemoveAll(path.Join(a.volumesDir(), uid)); err != nil {
			return err
		}
	}
	if s == nil || s.UID != uid {
		return nil
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

// volumeWait is how soon to look again while a volume isn't there yet.
const volumeWait = 3 * time.Second
