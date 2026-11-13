package cloudhypervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"kevaso.com/core/sdk/kri"
)

// Volumes on a VM (ADR 0006, research E029). A silo's volumes reach its guest two ways:
//
//   - a local volume (no host folder) is a thin LV of its own, attached as an extra virtio disk with
//     a serial the guest finds it by (/dev/disk/by-id/virtio-SERIAL), formatted once by the guest;
//   - a volume that is a folder on the host (a mount class's, mounted by the plugin's node side; or
//     a device class's, mounted by kevasod) is shared over virtiofs: one virtiofsd per folder, in
//     a locked-down unit of its own, and a --fs device on the VMM; the guest mounts it by tag. No
//     credential of the storage ever enters the VM, only the folder.
//
// The guest mounts both at their mount paths (MountGuestVolumes, then at every boot from fstab).
// A volume change restarts the VM (no hot-add). Stopping undoes it in order: the VMM first, then
// the virtiofsd daemons (they hold the folder open), and only then may kevasod or the node side
// unmount the folders, which is what lets a move's handoff say "unmounted" truthfully.

// VirtiofsdBin is virtiofsd (Ubuntu's package; E029 used 1.10).
const VirtiofsdBin = "/usr/libexec/virtiofsd"

// virtiofsd runs as root, bounded (VirtiofsdCaps), and chroots itself into its share before it
// serves anything (--sandbox=chroot, which virtiofsd 1.10 refuses to do for any other user, real
// machines showed). A separate user would gain nothing: CAP_SETUID, which it needs to act as the
// guest's callers, makes any user root. Once in the share it keeps only VirtiofsdKeeps and empties
// its bounding set, so it can't chroot out again.

// VirtiofsdCaps bound what virtiofsd may ever hold, and why:
//   - CAP_CHOWN, CAP_FOWNER, CAP_DAC_OVERRIDE: the guest's root owns and changes files of any user
//     in its volume; virtiofsd acts for it on the host;
//   - CAP_SETUID, CAP_SETGID: it switches its file-system identity to the guest caller's, so
//     files are created with the guest's owners;
//   - CAP_SYS_CHROOT: --sandbox=chroot, so it can't see anything but the shared folder (it drops it
//     once in);
//   - CAP_SETPCAP: to drop its own capabilities and bounding set for the serving process (without
//     it virtiofsd fails: "can't apply the child capabilities").
//
// Left out on purpose: CAP_MKNOD (no device nodes from a guest on the host's disks), CAP_SETFCAP
// and CAP_FSETID (no file capabilities, no set-uid or set-gid files: a volume is data, never a way
// into the host); CAP_SYS_ADMIN and CAP_SYS_RESOURCE (no namespaces, no raised limits: the unit
// sets LimitNOFILE and virtiofsd leaves it alone). VirtiofsdDrops tells virtiofsd not to ask for them.
var VirtiofsdCaps = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT"}

// VirtiofsdDefaults are the capabilities virtiofsd 1.10 keeps for serving unless told otherwise
// (--modcaps); each must be in VirtiofsdCaps or in VirtiofsdDrops, or it exits at start.
var VirtiofsdDefaults = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_SETGID", "CAP_SETUID", "CAP_MKNOD", "CAP_SETFCAP"}

// VirtiofsdDrops are virtiofsd's defaults it's told to leave out (--modcaps=-…).
var VirtiofsdDrops = []string{"CAP_FSETID", "CAP_MKNOD", "CAP_SETFCAP"}

// modcaps is VirtiofsdDrops as virtiofsd's --modcaps value (-fsetid:-mknod:…).
func modcaps() string {
	parts := make([]string, len(VirtiofsdDrops))
	for i, c := range VirtiofsdDrops {
		parts[i] = "-" + strings.ToLower(strings.TrimPrefix(c, "CAP_"))
	}
	return strings.Join(parts, ":")
}

// VolumeDisk is a local volume: a thin LV attached as an extra disk.
type VolumeDisk struct {
	Name, MountPath string
	SizeBytes       int64
	LV              string // in VG
	Serial          string // the guest sees /dev/disk/by-id/virtio-SERIAL (≤ 20 characters)
}

// Device is the LV's path on the host.
func (d VolumeDisk) Device() string { return "/dev/" + VG + "/" + d.LV }

// Share is a host folder shared over virtiofs.
type Share struct {
	Name, MountPath string
	HostPath        string // the folder on the host
	Tag             string // the guest mounts it by this (≤ 36 characters)
	Unit            string // its virtiofsd's systemd unit
	Socket          string // the vhost-user socket between virtiofsd and the VMM, in the silo's directory
}

// Layout is how a silo's disks and volumes are laid out on the host.
type Layout struct {
	Disks  []VolumeDisk
	Shares []Share
	// RootFile is the root disk as an image file on a mount class's folder (spec.disk.class), so it
	// moves with the silo; "" for the thin LV.
	RootFile string
}

// RootDisk is what the VMM boots from.
func (l Layout) RootDisk(n Names) string {
	if l.RootFile != "" {
		return l.RootFile
	}
	return "/dev/" + VG + "/" + n.LV
}

// volKey is a stable short name for one of a silo's volumes.
func volKey(n Names, name string) string {
	h := sha256.Sum256([]byte(n.Short + "/" + name))
	return hex.EncodeToString(h[:4])
}

// RootImage is the root disk's file name in its folder.
const RootImage = "root.raw"

// LayoutFor lays out a silo's volumes (sorted by name, so units are stable).
func LayoutFor(n Names, vols []kri.Volume, diskHostPath string) Layout {
	vs := append([]kri.Volume(nil), vols...)
	slices.SortFunc(vs, func(a, b kri.Volume) int { return strings.Compare(a.Name, b.Name) })
	var l Layout
	for _, v := range vs {
		k := volKey(n, v.Name)
		if v.HostPath == "" {
			l.Disks = append(l.Disks, VolumeDisk{Name: v.Name, MountPath: v.MountPath, SizeBytes: v.SizeBytes,
				LV: n.LV + "-" + k, Serial: "kv" + k})
			continue
		}
		l.Shares = append(l.Shares, Share{Name: v.Name, MountPath: v.MountPath, HostPath: v.HostPath, Tag: "kv" + k,
			Unit:   unitPrefix + n.Short + "-fs-" + k + ".service",
			Socket: n.Dir + "/vfs/" + k + ".sock"})
	}
	if diskHostPath != "" {
		l.RootFile = path.Join(diskHostPath, RootImage)
	}
	return l
}

// VMMArgs are the VMM's disk, share and memory arguments for a layout (E029: virtiofs needs the
// guest's memory shared with virtiofsd, memory shared=on).
func VMMArgs(n Names, l Layout, memMiB int64) []string {
	mem := "size=" + strconv.FormatInt(memMiB, 10) + "M"
	if len(l.Shares) > 0 {
		mem += ",shared=on"
	}
	args := []string{"--memory", mem, "--disk", "path=" + l.RootDisk(n) + ",image_type=raw", "path=" + n.Dir + "/seed.img,readonly=on,image_type=raw"}
	for _, d := range l.Disks {
		args = append(args, "path="+d.Device()+",image_type=raw,serial="+d.Serial)
	}
	for _, s := range l.Shares {
		args = append(args, "--fs", "tag="+s.Tag+",socket="+s.Socket)
	}
	return args
}

// VirtiofsdArgs are one share's virtiofsd arguments (E029: --cache=auto, --sandbox=chroot). The
// unit sets the open-files limit, so virtiofsd doesn't try to raise it (--rlimit-nofile=0); its
// socket is the VMM's group's (virtiofsd makes it 0700 otherwise), and it drops VirtiofsdDrops.
func VirtiofsdArgs(s Share) []string {
	return []string{"--socket-path=" + s.Socket, "--socket-group=" + VMMUser, "--shared-dir=" + s.HostPath, "--cache=auto",
		"--sandbox=chroot", "--rlimit-nofile=0", "--modcaps=" + modcaps()}
}

// VirtiofsdUnit is one share's virtiofsd: root bounded by VirtiofsdCaps (see there), its socket the
// VMM's group's (so only the VMM can connect), no network, no devices, and of the host's files only
// the shared folder and its socket's folder: the control plane's data, other silos and their
// shares, /run (the admin socket) and Kevaso's keys are out of sight. It serves one VMM connection
// and exits with it, so systemd starts it again at once: a reboot inside the guest is the VMM
// reconnecting (it waits up to a minute for the socket), not a new start through StartPlan.
// Stopping is StopPlan's systemctl stop, which never restarts it.
//
// No ProcSubset=pid: virtiofsd reads /proc/sys/fs/nr_open at start, even with --rlimit-nofile=0.
func VirtiofsdUnit(n Names, s Share) string {
	caps := strings.Join(VirtiofsdCaps, " ")
	return `[Unit]
Description=Kevaso silo ` + n.Short + `: virtiofsd for volume ` + s.Name + `

[Service]
# Root's own group: virtiofsd keeps its own credentials for the guest's root (uid 0, gid 0), so
# files that root makes in the share get this group, and must get gid 0. The socket's group is
# --socket-group's.
User=root
Group=root
ExecStartPre=+/bin/rm -f ` + s.Socket + `
ExecStart=` + VirtiofsdBin + ` ` + strings.Join(VirtiofsdArgs(s), " ") + `
Restart=always
RestartSec=100ms
LimitNOFILE=1048576
CapabilityBoundingSet=` + caps + `
# virtiofsd fails to apply its own capabilities ("failed to sync capabilities with the kernel")
# unless it starts with them ambient too.
AmbientCapabilities=` + caps + `
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
# Only the shared folder and the socket's folder: the rest of /var/lib/kevaso (the control plane's
# data, other silos' volumes), other silos' directories and /run (kevasod's admin socket) are empty.
TemporaryFileSystem=/var/lib/kevaso:ro ` + SilosDir + `:ro /run:ro
BindPaths=` + s.HostPath + ` ` + path.Dir(s.Socket) + `
InaccessiblePaths=/root -/etc/kevaso -/etc/ssh -` + ImagesDir + `
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
UMask=0007
`
}

// Step is one host command of a plan; Socket, if set, must exist before the next step.
type Step struct {
	Cmd    []string
	Socket string
}

// StartPlan starts a VM: each share's virtiofsd afresh (restart: one that served the last boot has
// exited), waiting for its socket, then the TAP and the VMM.
func StartPlan(n Names, l Layout) []Step {
	var p []Step
	for _, s := range l.Shares {
		p = append(p, Step{Cmd: []string{"systemctl", "restart", s.Unit}, Socket: s.Socket})
	}
	return append(p, Step{Cmd: []string{"ip", "link", "set", n.Tap, "up"}}, Step{Cmd: []string{"systemctl", "start", n.Unit}})
}

// StopPlan is what stopping does once the guest has powered off (or didn't): the VMM, then the
// virtiofsd daemons. Only after it is a shared folder free to unmount.
func StopPlan(n Names, l Layout) [][]string {
	p := [][]string{{"systemctl", "stop", n.Unit}, {"systemctl", "reset-failed", n.Unit}}
	for _, s := range l.Shares {
		p = append(p, []string{"systemctl", "stop", s.Unit}, []string{"systemctl", "reset-failed", s.Unit})
	}
	return p
}

// fstabEscape escapes a path for fstab (spaces and the like as octal).
func fstabEscape(p string) string {
	var b strings.Builder
	for _, c := range []byte(p) {
		if c == ' ' || c == '\t' || c == '\n' || c == '\\' {
			fmt.Fprintf(&b, `\%03o`, c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Fstab markers: the block the runtime owns in the guest's /etc/fstab.
const (
	fstabBegin = "# kevaso volumes: begin (written by the host, do not edit)"
	fstabEnd   = "# kevaso volumes: end"
)

// FstabBlock is the guest's fstab entries for a layout: mounted at every boot, and never holding
// a boot up if one is missing (nofail).
func FstabBlock(l Layout) string {
	lines := []string{fstabBegin}
	for _, d := range l.Disks {
		lines = append(lines, "/dev/disk/by-id/virtio-"+d.Serial+" "+fstabEscape(d.MountPath)+" ext4 noatime,nofail,x-systemd.device-timeout=30s 0 2")
	}
	for _, s := range l.Shares {
		lines = append(lines, s.Tag+" "+fstabEscape(s.MountPath)+" virtiofs nofail 0 0")
	}
	return strings.Join(append(lines, fstabEnd), "\n")
}

// GuestMountScript mounts a layout's volumes inside the guest (run as root through Exec): each new
// disk formatted once (only if it holds nothing at all), the fstab block replaced, then everything
// mounted, parents first. Idempotent.
func GuestMountScript(l Layout) string {
	var b strings.Builder
	b.WriteString("set -e\n")
	for _, d := range l.Disks {
		dev := "/dev/disk/by-id/virtio-" + d.Serial
		fmt.Fprintf(&b, `d=%s
i=0; while [ ! -b "$d" ]; do i=$((i+1)); [ $i -le 30 ] || { echo "no disk $d for volume %s" >&2; exit 1; }; sleep 1; done
set +e; t=$(blkid -p -o value -s TYPE "$d"); rc=$?; set -e
if [ $rc -eq 2 ]; then mkfs.ext4 -q -m 0 "$d"; elif [ $rc -ne 0 ] || [ -z "$t" ]; then echo "$d holds something blkid can't name: not formatting it" >&2; exit 1; fi
`, shellQuote([]string{dev}), d.Name)
	}
	fmt.Fprintf(&b, `tmp=$(mktemp)
sed '/^%s$/,/^%s$/d' /etc/fstab > "$tmp"
printf '%%s\n' %s >> "$tmp"
cat "$tmp" > /etc/fstab; rm -f "$tmp"
systemctl daemon-reload
`, sedQuote(fstabBegin), sedQuote(fstabEnd), shellQuote([]string{FstabBlock(l)}))
	var paths []string
	for _, d := range l.Disks {
		paths = append(paths, d.MountPath)
	}
	for _, s := range l.Shares {
		paths = append(paths, s.MountPath)
	}
	slices.Sort(paths) // a parent sorts before what's inside it
	for _, p := range paths {
		q := shellQuote([]string{p})
		fmt.Fprintf(&b, "mkdir -p %s; mountpoint -q %s || mount %s\n", q, q, q)
	}
	return b.String()
}

// sedQuote escapes a fixed line for a sed address inside the script's single quotes.
func sedQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `/`, `\/`, `.`, `\.`, `*`, `\*`, `[`, `\[`, `]`, `\]`, `^`, `\^`, `$`, `\$`, `'`, `'\''`)
	return r.Replace(s)
}

// volumesKey is what a silo's volumes are as the VM sees them (sizes aside: a local disk keeps its size).
func volumesKey(vols []kri.Volume) string {
	parts := make([]string, 0, len(vols))
	for _, v := range vols {
		parts = append(parts, v.Name+"\x00"+v.MountPath+"\x00"+v.HostPath)
	}
	slices.Sort(parts)
	return strings.Join(parts, "\x01")
}

// lvExists reports whether a logical volume is there.
func (r *Runtime) lvExists(ctx context.Context, lv string) bool {
	out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+lv)
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// applyLayout makes what a layout needs on the host and writes the units: new local disks (an LV
// that's there is kept: its data stays), the virtiofsd units (a share no longer there loses its
// unit), the VMM's unit. old is the layout before ("" root: none).
func (r *Runtime) applyLayout(ctx context.Context, st State, old, l Layout) error {
	n := NamesFor(st.ID)
	for _, d := range l.Disks {
		if r.lvExists(ctx, d.LV) {
			continue
		}
		size := d.SizeBytes
		if size <= 0 {
			size = DefaultVolumeBytes
		}
		if err := r.run(ctx, "lvcreate", "-q", "-T", VG+"/"+ThinPool, "-V", strconv.FormatInt((size+(1<<20)-1)>>20, 10)+"m", "-n", d.LV); err != nil {
			return err
		}
	}
	keep := map[string]bool{}
	if len(l.Shares) > 0 {
		if err := r.run(ctx, "install", "-d", "-m", "0750", "-o", "root", "-g", VMMUser, n.Dir+"/vfs"); err != nil {
			return err
		}
	}
	for _, s := range l.Shares {
		keep[s.Unit] = true
		if err := r.Host.WriteFile("/etc/systemd/system/"+s.Unit, []byte(VirtiofsdUnit(n, s)), 0o644); err != nil {
			return err
		}
	}
	for _, s := range old.Shares {
		if !keep[s.Unit] {
			_, _ = r.Host.Run(ctx, "systemctl", "stop", s.Unit)
			_ = r.Host.RemoveAll("/etc/systemd/system/" + s.Unit)
		}
	}
	if err := r.Host.WriteFile("/etc/systemd/system/"+n.Unit, []byte(UnitFor(n, st.cpus(), st.memMiB(), r.Firmware(), st.MAC, l)), 0o644); err != nil {
		return err
	}
	return r.run(ctx, "systemctl", "daemon-reload")
}

// DefaultVolumeBytes is a local volume's size when it gives none.
const DefaultVolumeBytes = 10 << 30

// SetVolumes implements kri.VolumeSetter.
func (r *Runtime) SetVolumes(ctx context.Context, id kri.ID, vols []kri.Volume) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state(id)
	if !ok {
		return false, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if volumesKey(st.Volumes) == volumesKey(vols) {
		return false, nil
	}
	n := NamesFor(id)
	if a := r.active(ctx, n.Unit); a == "active" || a == "activating" {
		return true, nil
	}
	old := st.layout()
	st.Volumes = vols
	if err := r.applyLayout(ctx, st, old, st.layout()); err != nil {
		return false, fmt.Errorf("volumes of %s: %w", id, err)
	}
	return false, r.saveState(st)
}

// MountGuestVolumes implements kri.GuestVolumes: the guest mounts the silo's volumes now, and at
// every boot from then on.
func (r *Runtime) MountGuestVolumes(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	l := st.layout()
	if len(l.Disks) == 0 && len(l.Shares) == 0 {
		return nil
	}
	var out strings.Builder
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	code, err := r.Exec(cctx, id, kri.ExecRequest{Command: []string{"sh", "-c", GuestMountScript(l)}, Stdout: &out, Stderr: &out})
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("exit %d: %s", code, strings.TrimSpace(out.String()))
	}
	return nil
}

var (
	_ kri.VolumeSetter = (*Runtime)(nil)
	_ kri.GuestVolumes = (*Runtime)(nil)
)
