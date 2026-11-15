// Package cloudhypervisor is the cloud-hypervisor runtime: each silo is a Cloud Hypervisor microVM
// with its own thin LVM disk, a TAP on the host's silo bridge, and a VMM locked down in its own
// systemd unit. Proven piece by piece in research E008 (boot + TAP), E009 (inbound/outbound), E010
// (VMM lockdown), E012 (thin LVM) and E036 (runs on GitHub's runners).
//
// All host changes go through the Host interface, so command sequences are unit-tested anywhere and
// the real thing runs only on Linux, as root (kevasod).
package cloudhypervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// Host runs commands and touches files on the machine. The real one is Local; tests use a fake.
type Host interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	ReadFile(path string) ([]byte, error)
	RemoveAll(path string) error
	Glob(pattern string) ([]string, error)
}

// State is what the runtime remembers about a silo (in its directory, silo.json).
type State struct {
	ID      kri.ID `json:"id"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	HostKey string `json:"hostKey"` // the guest's SSH host key (public), pinned for Exec
	Started bool   `json:"started"` // started at least once (Stopped vs Created)
	CPUs    int    `json:"cpus,omitempty"`
	MemMiB  int64  `json:"memMiB,omitempty"`
	// Volumes are what its VMM gets (local disks, shared folders); RootDir, if set, is the mount
	// class's folder holding its root disk image (spec.disk.class).
	Volumes []kri.Volume `json:"volumes,omitempty"`
	RootDir string       `json:"rootDir,omitempty"`
}

func (s State) layout() Layout { return LayoutFor(NamesFor(s.ID), s.Volumes, s.RootDir) }

func (s State) cpus() int {
	if s.CPUs > 0 {
		return s.CPUs
	}
	return 1
}

func (s State) memMiB() int64 {
	if s.MemMiB > 0 {
		return s.MemMiB
	}
	return 1024
}

// Runtime is the cloud-hypervisor runtime.
type Runtime struct {
	Host    Host
	Arch    string // x86_64 | aarch64
	ExecKey ssh.Signer
	ExecPub string // authorized_keys line for ExecKey
	DialSSH func(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error)
	Version string
	mu      sync.Mutex // allocations (IP) and create/delete
}

// Firmware is the firmware path for the host's CPU.
func (r *Runtime) Firmware() string {
	if r.Arch == "aarch64" {
		return BinDir + "/CLOUDHV_EFI.fd"
	}
	return BinDir + "/CLOUDHV.fd"
}

// Info implements kri.Runtime.
func (r *Runtime) Info() kri.Info {
	return kri.Info{Name: "cloud-hypervisor", Version: r.Version, Capabilities: kri.Capabilities{
		Isolation: "vm", Network: "nic", UDP: true, InboundServices: true, Persistence: "disk", Exec: true,
	}}
}

func (r *Runtime) run(ctx context.Context, name string, args ...string) error {
	out, err := r.Host.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *Runtime) states() ([]State, error) {
	paths, err := r.Host.Glob(SilosDir + "/*/silo.json")
	if err != nil {
		return nil, err
	}
	var out []State
	for _, p := range paths {
		b, err := r.Host.ReadFile(p)
		if err != nil {
			continue
		}
		var s State
		if json.Unmarshal(b, &s) == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *Runtime) state(id kri.ID) (State, bool) {
	b, err := r.Host.ReadFile(NamesFor(id).Dir + "/silo.json")
	if err != nil {
		return State{}, false
	}
	var s State
	if json.Unmarshal(b, &s) != nil || s.ID != id {
		return State{}, false
	}
	return s, true
}

// readState is a silo's state: absent (no file), or the error of a file that is there but can't be
// read or parsed. Never "absent" for a file that exists: Create would image a new root disk over
// the old one.
func (r *Runtime) readState(id kri.ID) (State, bool, error) {
	p := NamesFor(id).Dir + "/silo.json"
	b, err := r.Host.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("%s: %w (not touching the silo)", p, err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil || s.ID != id {
		return State{}, false, fmt.Errorf("%s is unreadable (%v): not touching the silo, its disk and volumes are kept", p, err)
	}
	return s, true, nil
}

// made says whether Create finished for a silo: its unit file is written last of all.
func (r *Runtime) made(id kri.ID) bool {
	_, err := r.Host.ReadFile("/etc/systemd/system/" + NamesFor(id).Unit)
	return err == nil
}

func (r *Runtime) saveState(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return r.Host.WriteFile(NamesFor(s.ID).Dir+"/silo.json", b, 0o600)
}

// Create implements kri.Runtime: disk from the image, cloud-init seed, TAP, VMM unit. Not started.
func (r *Runtime) Create(ctx context.Context, spec kri.Spec) error {
	if done, err := r.created(spec.ID); done || err != nil {
		return err
	}
	img, err := r.image(ctx, spec.Image) // before the lock: a first fetch takes a while
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if done, err := r.created(spec.ID); done || err != nil {
		return err
	}
	// A Create killed halfway (its state saved, its unit never written) made a silo that never
	// ran: nothing in it is anyone's data. Take it apart and make it afresh.
	if st, ok, _ := r.readState(spec.ID); ok && !st.Started {
		if err := r.deleteLocked(ctx, spec.ID); err != nil {
			return fmt.Errorf("redo a half-made %s: %w", spec.ID, err)
		}
	}
	n := NamesFor(spec.ID)
	// A root volume that is there with no state of its own is a disk of an earlier copy of this
	// silo (its state lost): data whose owner can't be proven from here. Never made over (review
	// claim B): it is kept, and the silo isn't made until a person decides.
	if spec.DiskHostPath == "" && r.lvExists(ctx, n.LV) {
		if _, ok, _ := r.readState(spec.ID); !ok {
			return fmt.Errorf("%s: root volume %s/%s is there with no state of this host's (%s/silo.json): not making the silo over it; "+
				"keep it (restore silo.json) or remove it yourself (lvremove %s/%s) to start afresh", spec.ID, VG, n.LV, n.Dir, VG, n.LV)
		}
	}
	IPMu.Lock() // container silos share the bridge and its addresses: until the state is saved
	ipLocked := true
	unlockIP := func() {
		if ipLocked {
			ipLocked = false
			IPMu.Unlock()
		}
	}
	defer unlockIP()
	ip, err := AllocateIP(UsedIPs(r.Host))
	if err != nil {
		return err
	}
	disk := spec.DiskBytes
	if disk <= 0 {
		disk = 20 << 30
	}
	mem := spec.Memory
	if mem <= 0 {
		mem = 1 << 30
	}
	cpus := spec.CPU
	if cpus <= 0 {
		cpus = 1
	}
	hostPub, hostPriv, err := newHostKey()
	if err != nil {
		return err
	}
	st := State{ID: spec.ID, IP: ip.String(), MAC: MAC(spec.ID), HostKey: hostPub, CPUs: cpus, MemMiB: mem >> 20,
		Volumes: spec.Volumes, RootDir: spec.DiskHostPath}
	layout := st.layout()

	if err := r.run(ctx, "install", "-d", "-m", "0700", "-o", VMMUser, "-g", VMMUser, n.Dir); err != nil {
		return err
	}
	if err := r.saveState(st); err != nil { // first: from here on, Delete knows what to clean up
		return err
	}
	unlockIP()
	steps := []func() error{
		func() error { return r.rootDisk(ctx, n, layout, img, disk, false) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, hostPriv, hostPub)), 0o600)
		},
		func() error { return r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(spec.ID, hostPub)), 0o600) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/network-config", []byte(NetworkConfig(st.MAC, ip, spec.ID.Namespace)), 0o600)
		},
		func() error {
			return r.run(ctx, "cloud-localds", "--network-config="+n.Dir+"/network-config", n.Dir+"/seed.img", n.Dir+"/user-data", n.Dir+"/meta-data")
		},
		// The seed carries the guest's host key: once built, keep only the image (owned by the VMM).
		func() error { return r.run(ctx, "rm", "-f", n.Dir+"/user-data") },
		func() error { return r.run(ctx, "chown", VMMUser+":"+VMMUser, n.Dir+"/seed.img") },
		func() error { return r.run(ctx, "ip", "tuntap", "add", "dev", n.Tap, "mode", "tap", "user", VMMUser) },
		func() error { return r.run(ctx, "ip", "link", "set", n.Tap, "master", Bridge, "up") },
		func() error { return r.applyLayout(ctx, st, Layout{}, layout) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			_ = r.deleteLocked(context.WithoutCancel(ctx), spec.ID)
			return fmt.Errorf("create %s: %w", spec.ID, err)
		}
	}
	return nil
}

// created says whether a silo is there and finished. A state that can't be read is an error, and
// so is a silo that ran but has no unit (nothing is redone over a disk that held data).
func (r *Runtime) created(id kri.ID) (bool, error) {
	st, ok, err := r.readState(id)
	switch {
	case err != nil:
		return false, err
	case !ok:
		return false, nil
	case r.made(id):
		return true, nil
	case st.Started:
		return false, fmt.Errorf("%s ran but its unit is gone: not making it again over its disk (delete the silo to start over)", id)
	}
	return false, nil // half-made: Create redoes it
}

func newHostKey() (pub, privPEM string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	blk, err := ssh.MarshalPrivateKey(sk, "")
	if err != nil {
		return "", "", err
	}
	sp, err := ssh.NewPublicKey(pk)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))), string(pem.EncodeToMemory(blk)), nil
}

// Start implements kri.Runtime.
func (r *Runtime) Start(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	n := NamesFor(id)
	// A TAP doesn't outlive a reboot of the host: make it again, as Create did.
	if _, err := r.Host.Run(ctx, "ip", "link", "show", n.Tap); err != nil {
		if err := r.run(ctx, "ip", "tuntap", "add", "dev", n.Tap, "mode", "tap", "user", VMMUser); err != nil {
			return err
		}
		if err := r.run(ctx, "ip", "link", "set", n.Tap, "master", Bridge); err != nil {
			return err
		}
	}
	for _, step := range StartPlan(n, st.layout()) {
		if err := r.run(ctx, step.Cmd[0], step.Cmd[1:]...); err != nil {
			return err
		}
		if step.Socket != "" {
			if err := r.waitFor(ctx, step.Socket); err != nil {
				return err
			}
		}
	}
	if !st.Started {
		st.Started = true
		return r.saveState(st)
	}
	return nil
}

// waitFor waits for a share's socket (systemd made it once it's there).
func (r *Runtime) waitFor(ctx context.Context, socket string) error {
	for deadline := time.Now().Add(10 * time.Second); ; {
		if m, _ := r.Host.Glob(socket); len(m) > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("virtiofsd never made %s", socket)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Stop implements kri.Runtime: ask the guest to power off, then stop the unit if it doesn't, then
// its virtiofsd daemons (StopPlan).
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	n := NamesFor(id)
	if r.active(ctx, n.Unit) == "active" {
		_, _ = r.Host.Run(ctx, BinDir+"/ch-remote", "--api-socket", n.Socket, "power-button")
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) && r.active(ctx, n.Unit) == "active" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
	for _, c := range StopPlan(n, st.layout()) {
		_, _ = r.Host.Run(ctx, c[0], c[1:]...)
	}
	return r.gone(ctx, id, "a stop")
}

func (r *Runtime) active(ctx context.Context, unit string) string {
	out, _ := r.Host.Run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(string(out))
}

// vmm says what systemd says of the VMM's unit, and whether a process of it may still run. Only a
// unit that is inactive or failed, with no main process and no process left in its cgroup, has
// gone: every other state (activating, deactivating, reloading, one systemctl doesn't answer) may
// still run the guest, and the fences take "not up" for stopped.
func (r *Runtime) vmm(ctx context.Context, unit string) (state string, up bool) {
	state = r.active(ctx, unit)
	switch state {
	case "inactive", "failed", "":
	default:
		return state, true
	}
	out, err := r.Host.Run(ctx, "systemctl", "show", "--property=MainPID,ControlGroup", unit)
	if err != nil {
		return state, true // can't say: not gone
	}
	for l := range strings.Lines(string(out)) {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch {
		case k == "MainPID" && v != "" && v != "0":
			return state, true
		case k == "ControlGroup" && v != "":
			procs, err := r.Host.ReadFile("/sys/fs/cgroup" + v + "/cgroup.procs")
			if (err != nil && !errors.Is(err, os.ErrNotExist)) || len(bytes.TrimSpace(procs)) > 0 {
				return state, true
			}
		}
	}
	return state, false
}

// gone confirms the VMM is gone after a stop or a kill.
func (r *Runtime) gone(ctx context.Context, id kri.ID, how string) error {
	if state, up := r.vmm(ctx, NamesFor(id).Unit); up {
		return fmt.Errorf("%s: the VMM may still run after %s (its unit is %q, or a process of it is left)", id, how, state)
	}
	return nil
}

// Delete implements kri.Runtime: everything the silo owns on the host.
func (r *Runtime) Delete(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deleteLocked(ctx, id)
}

// deleteLocked removes what the silo owns on this host: its units (VMM first, then virtiofsd),
// TAP, LVs (root and local volumes) and directory. A root disk image on a mount class's folder is
// the volume's, not this host's: it stays (the silo may have moved; deleting the silo deletes the
// volume through its plugin).
func (r *Runtime) deleteLocked(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return nil
	}
	n := NamesFor(id)
	l := st.layout()
	for _, c := range StopPlan(n, l) {
		_, _ = r.Host.Run(ctx, c[0], c[1:]...)
	}
	_ = r.Host.RemoveAll("/etc/systemd/system/" + n.Unit)
	for _, s := range l.Shares {
		_ = r.Host.RemoveAll("/etc/systemd/system/" + s.SocketUnit)
		_ = r.Host.RemoveAll("/etc/systemd/system/" + s.Unit)
	}
	_, _ = r.Host.Run(ctx, "systemctl", "daemon-reload")
	_, _ = r.Host.Run(ctx, "ip", "link", "del", n.Tap)
	lvs := []string{}
	if l.RootFile == "" {
		lvs = append(lvs, n.LV)
	}
	// Every local volume it ever had (one dropped from the spec is kept until the silo goes).
	if out, err := r.Host.Run(ctx, "lvs", "--noheadings", "-o", "lv_name", VG); err == nil {
		for _, f := range strings.Fields(string(out)) {
			if strings.HasPrefix(f, n.LV+"-") {
				lvs = append(lvs, f)
			}
		}
	}
	for _, lv := range lvs {
		if out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+lv); err == nil && len(bytes.TrimSpace(out)) > 0 {
			if err := r.run(ctx, "lvremove", "-q", "-y", VG+"/"+lv); err != nil {
				return err
			}
		}
	}
	return r.Host.RemoveAll(n.Dir)
}

// rootDisk makes the silo's root disk from its image: a thin LV, or an image file on a mount
// class's folder. An image file already there is the silo's disk come from another host: it's
// kept, unless fresh (a reset) asks for a new one.
func (r *Runtime) rootDisk(ctx context.Context, n Names, l Layout, img string, size int64, fresh bool) error {
	if l.RootFile == "" {
		if r.lvExists(ctx, n.LV) {
			if !fresh {
				return fmt.Errorf("root volume %s/%s is there already: only a reset makes it afresh", VG, n.LV)
			}
			if err := r.run(ctx, "lvremove", "-q", "-y", VG+"/"+n.LV); err != nil {
				return err
			}
		}
		if err := r.run(ctx, "lvcreate", "-q", "-T", VG+"/"+ThinPool, "-V", strconv.FormatInt(size>>20, 10)+"m", "-n", n.LV); err != nil {
			return err
		}
		return r.run(ctx, "qemu-img", "convert", "-n", "--target-is-zero", "-O", "raw", img, "/dev/"+VG+"/"+n.LV)
	}
	if _, err := r.Host.Run(ctx, "test", "-e", l.RootFile); err == nil && !fresh {
		return nil // moved here with its data
	}
	tmp := l.RootFile + ".new"
	for _, c := range RootFilePlan(img, tmp, l.RootFile, size) {
		if err := r.run(ctx, c[0], c[1:]...); err != nil {
			_ = r.Host.RemoveAll(tmp)
			return err
		}
	}
	return nil
}

// RootFilePlan makes a root disk image file from an image: written next to it, grown to the disk's
// size (never shrunk), made the VMM's alone (qemu-img leaves it world-readable: the whole disk),
// then put in place, so a half-written image is never booted.
func RootFilePlan(img, tmp, file string, size int64) [][]string {
	return [][]string{
		{"rm", "-f", tmp},
		{"qemu-img", "convert", "-O", "raw", img, tmp},
		{"qemu-img", "resize", "-f", "raw", tmp, strconv.FormatInt(size, 10)},
		{"chown", VMMUser + ":" + VMMUser, tmp},
		{"chmod", "0600", tmp},
		{"mv", "-f", tmp, file},
	}
}

// Status implements kri.Runtime.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	st, ok, err := r.readState(id)
	if err != nil {
		// Never "absent" (K-094: a fence would count it stopped), and never made again: Running
		// while its VMM runs, else Failed, saying why.
		if _, up := r.vmm(ctx, NamesFor(id).Unit); up {
			return kri.Status{State: kri.Running, Message: err.Error()}, nil
		}
		return kri.Status{State: kri.Failed, Message: err.Error() + ": its VMM doesn't run; delete the silo, or restore the file, to go on"}, nil
	}
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	if !st.Started && !r.made(id) {
		// Half-made (kevasod killed in Create, before the unit): absent, so it's created again
		// (Create redoes it); never started, so there's no disk of a running silo to keep.
		return kri.Status{State: kri.Absent}, nil
	}
	switch state, up := r.vmm(ctx, NamesFor(id).Unit); {
	case up && state == "active":
		return kri.Status{State: kri.Running, Address: st.IP}, nil
	case up:
		return kri.Status{State: kri.Running, Address: st.IP, Message: "its VMM's unit is " + strconv.Quote(state) + " and may still run"}, nil
	case state == "failed":
		out, _ := r.Host.Run(ctx, "journalctl", "-u", NamesFor(id).Unit, "-n", "3", "--no-pager", "-o", "cat")
		return kri.Status{State: kri.Failed, Message: strings.TrimSpace(string(out))}, nil
	}
	if st.Started {
		return kri.Status{State: kri.Stopped}, nil
	}
	return kri.Status{State: kri.Created}, nil
}

// List implements kri.Runtime.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	all, err := r.states()
	if err != nil {
		return nil, err
	}
	ids := make([]kri.ID, 0, len(all))
	for _, s := range all {
		ids = append(ids, s.ID)
	}
	return ids, nil
}

// Exec implements kri.Runtime: SSH to the guest over the bridge as root with the exec key (only
// this host holds it), with the guest's host key pinned, then argv. It waits for the guest's SSH
// to come up (first boot). No sudo: see UserData for who can still see a command line.
func (r *Runtime) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	st, ok := r.state(id)
	if !ok {
		return -1, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if s, _ := r.Status(ctx, id); s.State != kri.Running {
		return -1, fmt.Errorf("%s is %s, not running", id, s.State)
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(st.HostKey))
	if err != nil {
		return -1, err
	}
	cfg := &ssh.ClientConfig{
		User:              ExecUser,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(r.ExecKey)},
		HostKeyCallback:   ssh.FixedHostKey(pinned),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           5 * time.Second,
	}
	dial := r.DialSSH
	if dial == nil {
		dial = dialSSH
	}
	var c *ssh.Client
	for {
		c, err = dial(ctx, net.JoinHostPort(st.IP, "22"), cfg)
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "host key mismatch") {
			return -1, fmt.Errorf("ssh to %s: the guest's host key isn't the one it was created with: %w", id, err)
		}
		select { // still booting
		case <-ctx.Done():
			return -1, fmt.Errorf("ssh to %s: %w (last: %v)", id, ctx.Err(), err)
		case <-time.After(2 * time.Second):
		}
	}
	defer func() { _ = c.Close() }()
	return runGuest(ctx, c, req)
}

// runGuest runs req on the guest over ssh, as root. The command carries a marker in its
// environment; if ctx is cancelled (the client went away) the session is signalled and closed,
// and a second session sweeps it (hostexec.SweepScript), since sshd doesn't kill a command
// without a terminal when its channel closes: everything with the marker and in the ssh session
// (sshd makes each one a session), so a command that cleared its environment goes too.
func runGuest(ctx context.Context, c *ssh.Client, req kri.ExecRequest) (int, error) {
	sess, err := c.NewSession()
	if err != nil {
		return -1, err
	}
	defer func() { _ = sess.Close() }()
	// The session copies stdout and stderr in two goroutines: one lock for both, and only Write
	// (a bytes.Buffer's ReadFrom, used by io.Copy, isn't safe to share: given as both, as callers
	// do, the stream that ended last cut off what the other had written).
	var mu sync.Mutex
	sess.Stdin, sess.Stdout, sess.Stderr = req.Stdin, &lockedWriter{mu: &mu, w: orDiscard(req.Stdout)}, &lockedWriter{mu: &mu, w: orDiscard(req.Stderr)}
	if req.TTY != nil {
		sz := req.TTY.Size
		if sz.Rows == 0 || sz.Cols == 0 {
			sz = kri.WindowSize{Rows: 24, Cols: 80}
		}
		if err := sess.RequestPty("xterm-256color", int(sz.Rows), int(sz.Cols), ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
			return -1, fmt.Errorf("terminal: %w", err)
		}
		sess.Stderr = nil // the terminal carries both
	}
	marker := hostexec.NewMarker()
	// Root's shell runs this one simple command by exec'ing it: no shell stays behind with the
	// command line, and nothing logs it.
	if err := sess.Start("exec env " + kri.ExecMarkerEnv + "=" + marker + " " + shellQuote(req.Command)); err != nil {
		return -1, err
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	var resize <-chan kri.WindowSize
	if req.TTY != nil {
		resize = req.TTY.Resize
	}
	for {
		select {
		case sz, ok := <-resize:
			if !ok {
				resize = nil
				continue
			}
			_ = sess.WindowChange(int(sz.Rows), int(sz.Cols))
		case err := <-done:
			var exitErr *ssh.ExitError
			switch {
			case err == nil:
				return 0, nil
			case errors.As(err, &exitErr):
				return exitErr.ExitStatus(), nil
			default:
				return -1, err
			}
		case <-ctx.Done():
			_ = sess.Signal(ssh.SIGKILL)
			_ = sess.Close()
			if sw, err := c.NewSession(); err == nil {
				_ = sw.Run("sh -c " + shellQuote([]string{hostexec.SweepScript}) + " sh " + marker)
				_ = sw.Close()
			}
			return -1, ctx.Err()
		}
	}
}

// lockedWriter writes under a lock shared with the session's other output, and is only a Writer.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func dialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(cc, chans, reqs), nil
}

// image is the local file of an image: a built-in name's (fetched at install), or an Image
// version's disk (URL#sha256=HEX: fetched once, checked against its hash).
func (r *Runtime) image(ctx context.Context, image string) (string, error) {
	url, sum, ok := kri.ParseDiskImage(image)
	if !ok {
		return imagePath(image, r.Arch)
	}
	dst := filepath.Join(ImagesDir, "sha256-"+sum+".img")
	if err := Fetch(ctx, r.Host, Asset{URL: url, SHA256: sum, File: filepath.Base(dst)}, dst, 0o600); err != nil {
		return "", fmt.Errorf("image %s: %w", url, err)
	}
	return dst, nil
}

// Reset implements kri.Resetter: the VM is stopped, its disk is made afresh from spec's image and
// its seed (with a new guest host key) rebuilt; its address, MAC and tap stay.
func (r *Runtime) Reset(ctx context.Context, spec kri.Spec) error {
	return r.ResetGated(ctx, spec, nil)
}

// ResetGated is Reset that asks gate (if set) once the VM is stopped and gone, right before its
// root disk is made afresh: the last thing before lvremove. An error from gate ends the reset with
// the disk as it was, and is returned as is.
func (r *Runtime) ResetGated(ctx context.Context, spec kri.Spec, gate func(context.Context) error) error {
	img, err := r.image(ctx, spec.Image)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state(spec.ID)
	if !ok {
		return fmt.Errorf("%s: %w", spec.ID, kri.ErrNotFound)
	}
	ip, err := netip.ParseAddr(st.IP)
	if err != nil {
		return err
	}
	n := NamesFor(spec.ID)
	disk := spec.DiskBytes
	if disk <= 0 {
		disk = 20 << 30
	}
	mem := spec.Memory
	if mem <= 0 {
		mem = 1 << 30
	}
	cpus := spec.CPU
	if cpus <= 0 {
		cpus = 1
	}
	hostPub, hostPriv, err := newHostKey()
	if err != nil {
		return err
	}
	old := st.layout()
	st.CPUs, st.MemMiB, st.Volumes, st.RootDir = cpus, mem>>20, spec.Volumes, spec.DiskHostPath
	layout := st.layout()
	steps := []func() error{
		func() error {
			for _, c := range StopPlan(n, old) {
				_, _ = r.Host.Run(ctx, c[0], c[1:]...)
			}
			return r.gone(ctx, spec.ID, "a stop") // its disk is made afresh next: never under a VMM
		},
		func() error {
			if gate != nil {
				return gate(ctx)
			}
			return nil
		},
		func() error { return r.rootDisk(ctx, n, layout, img, disk, true) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, hostPriv, hostPub)), 0o600)
		},
		func() error { return r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(spec.ID, hostPub)), 0o600) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/network-config", []byte(NetworkConfig(st.MAC, ip, spec.ID.Namespace)), 0o600)
		},
		func() error {
			return r.run(ctx, "cloud-localds", "--network-config="+n.Dir+"/network-config", n.Dir+"/seed.img", n.Dir+"/user-data", n.Dir+"/meta-data")
		},
		func() error { return r.run(ctx, "rm", "-f", n.Dir+"/user-data") },
		func() error { return r.run(ctx, "chown", VMMUser+":"+VMMUser, n.Dir+"/seed.img") },
		func() error { return r.applyLayout(ctx, st, old, layout) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("reset %s: %w", spec.ID, err)
		}
	}
	st.HostKey, st.Started = hostPub, false
	return r.saveState(st)
}

// imagePath maps an image name to its cached file.
func imagePath(image, arch string) (string, error) {
	a, ok := Images[image]
	if !ok {
		return "", fmt.Errorf("unknown image %q (known: ubuntu-24.04)", image)
	}
	f, ok := a[arch]
	if !ok {
		return "", fmt.Errorf("image %q has no %s build", image, arch)
	}
	return filepath.Join(ImagesDir, f.File), nil
}

var _ kri.Runtime = (*Runtime)(nil)
