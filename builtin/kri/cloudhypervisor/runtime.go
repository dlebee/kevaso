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
	"os/exec"
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
	// Made is set once the unit file is written, and a reset keeps it. Started is cleared by a
	// finished reset, so it cannot say whether this silo was ever finished: a missing unit after
	// that is not a half-made create, and the disk stays.
	Made   bool  `json:"made,omitempty"`
	CPUs   int   `json:"cpus,omitempty"`
	MemMiB int64 `json:"memMiB,omitempty"`
	// Volumes are what its VMM gets (local disks, shared folders); RootDir, if set, is the mount
	// class's folder holding its root disk image (spec.disk.class).
	Volumes []kri.Volume `json:"volumes,omitempty"`
	RootDir string       `json:"rootDir,omitempty"`
	// Remake, if set, says its root disk is being made afresh (a reset) and isn't to be trusted:
	// saved before the first destructive step (lvremove), cleared after the last. A reset cut
	// there (kevasod stopped, a kill) is finished by the next Start before the VM boots, and the
	// half-made disk never boots (review-batch4 claim 2).
	Remake *Remake `json:"remake,omitempty"`
}

// Remake is a reset under way: the image its root disk is made from and the disk's size, and
// the layout it had before (its shares are taken down as the reset does).
type Remake struct {
	Image      string       `json:"image"`
	DiskBytes  int64        `json:"diskBytes"`
	OldVolumes []kri.Volume `json:"oldVolumes,omitempty"`
	OldRootDir string       `json:"oldRootDir,omitempty"`
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
	// ExecCheck, if set, replaces ExecCheckEvery (tests).
	ExecCheck time.Duration
	mu        sync.Mutex // allocations (IP) and create/delete
}

// ExecCheckEvery is how often an Exec looks again at whether the silo's VMM still runs, while it
// waits for the guest's SSH and while its command runs: a VMM that exited ends it. Without it, an
// Exec into a VM whose VMM was killed waited for ever (the guest's SSH never came up, or a
// session's TCP connection to a guest that is gone never ended), and so did the silo's reconcile
// (found on the machines: a VM killed twice was never restarted, nor its delete processed).
const ExecCheckEvery = 2 * time.Second

// errVMMGone: the VMM of the silo an Exec ran in exited meanwhile.
var errVMMGone = errors.New("its VMM no longer runs")

// whileUp is ctx, ended (errVMMGone) once Status says the silo doesn't run. stop ends the watch.
func (r *Runtime) whileUp(ctx context.Context, id kri.ID) (context.Context, func()) {
	every := r.ExecCheck
	if every <= 0 {
		every = ExecCheckEvery
	}
	wctx, cancel := context.WithCancelCause(ctx)
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
			}
			if st, err := r.Status(wctx, id); err == nil && st.State != kri.Running && wctx.Err() == nil {
				cancel(fmt.Errorf("%s: %w (%s)", id, errVMMGone, st.State))
				return
			}
		}
	}()
	return wctx, func() { cancel(nil) }
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
	if name == "qemu-img" && len(args) > 0 && args[0] == "convert" {
		return r.convertImage(ctx, args[1:])
	}
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
	img, err := r.image(ctx, spec.Image, spec.DiskBytes) // before the lock: a first fetch takes a while
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if done, err := r.created(spec.ID); done || err != nil {
		return err
	}
	// A Create killed halfway (its state saved, its unit never written, Made never set) made a
	// silo that never ran: nothing in it is anyone's data. Take it apart and make it afresh.
	// A silo that was made, including one a reset has stopped calling started, is left as it is.
	if st, ok, _ := r.readState(spec.ID); ok && !st.Made && !st.Started {
		if err := r.deleteLocked(ctx, spec.ID); err != nil {
			return fmt.Errorf("redo a half-made %s: %w", spec.ID, err)
		}
	}
	n := NamesFor(spec.ID)
	// A root volume that is there with no state of its own is a disk of an earlier copy of this
	// silo (its state lost): data whose owner can't be proven from here. Never made over (review
	// claim B): it is kept, and the silo isn't made until a person decides. A failed lvs is not
	// "absent": Create returns before it saves state, and removes nothing.
	if spec.DiskHostPath == "" {
		present, err := r.lvExists(ctx, n.LV)
		if err != nil { // a failed lvs is never "no volume"
			return fmt.Errorf("%s: root volume %s/%s could not be checked (%w): not making the silo and removing nothing", spec.ID, VG, n.LV, err)
		}
		if present {
			if _, ok, _ := r.readState(spec.ID); !ok {
				return fmt.Errorf("%s: root volume %s/%s is there with no state of this host's (%s/silo.json): not making the silo over it; "+
					"keep it (restore silo.json) or remove it yourself (lvremove %s/%s) to start afresh", spec.ID, VG, n.LV, n.Dir, VG, n.LV)
			}
		}
	}
	// The same for its local volumes (K-111): one there with no state is an earlier copy's data.
	// Made over, it was taken into the new silo, and a failed step's clean-up removed it.
	if _, ok, _ := r.readState(spec.ID); !ok {
		out, lerr := r.Host.Run(ctx, "lvs", "--noheadings", "-o", "lv_name", VG)
		if lerr != nil {
			return fmt.Errorf("%s: logical volumes in %s could not be listed (%w): not making the silo until they can", spec.ID, VG, lerr)
		}
		for _, f := range strings.Fields(string(out)) {
			if f == n.LV || strings.HasPrefix(f, n.LV+"-") { // the root LV's own name, not only its local volumes
				return fmt.Errorf("%s: local volume %s/%s is there with no state of this host's (%s/silo.json): not making the silo over it; "+
					"keep it (restore silo.json) or remove it yourself (lvremove %s/%s) to start afresh", spec.ID, VG, f, n.Dir, VG, f)
			}
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
	used, err := UsedIPs(r.Host)
	if err != nil {
		return err
	}
	ip, err := AllocateIP(used)
	if err != nil {
		return err
	}
	disk := diskBytesOrDefault(spec.DiskBytes)
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
	if spec.GuestHostKey != "" && spec.DiskHostPath != "" { // trust a reported key only for a disk that travels
		file := filepath.Join(spec.DiskHostPath, RootImage)
		_, probeErr := r.Host.Run(ctx, "test", "-e", file)
		missing, merr := probeMissing(probeErr)
		if merr == nil && !missing { // the image is already the guest's
			pub := strings.TrimSpace(spec.GuestHostKey)
			if _, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(pub)); perr != nil {
				return fmt.Errorf("guest host key: %w", perr)
			}
			hostPub, hostPriv = pub, ""
		}
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
	madeRoot := false
	steps := []func() error{
		func() error {
			made, err := r.rootDisk(ctx, n, layout, img, disk, false)
			if made {
				madeRoot = true
			}
			return err
		},
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
			_ = r.deleteLockedRoot(context.WithoutCancel(ctx), spec.ID, madeRoot) // the root LV goes only if this Create made it
			return fmt.Errorf("create %s: %w", spec.ID, err)
		}
	}
	st.Made = true // the unit is written: a later loss of it is not a half-made create
	if err := r.saveState(st); err != nil {
		return fmt.Errorf("create %s: %w", spec.ID, err)
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
	case st.Made || st.Started:
		return false, fmt.Errorf("%s was made but its unit is gone: not making it again over its disk (delete the silo to start over)", id)
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

// GuestHostKey implements kri.GuestHostKeySource.
func (r *Runtime) GuestHostKey(id kri.ID) (string, bool) {
	st, ok := r.state(id)
	key := strings.TrimSpace(st.HostKey)
	if !ok || key == "" {
		return "", false
	}
	return key, true
}

// SetGuestHostKey implements kri.GuestHostKeySetter. A disk that travelled keeps the guest's
// host key; this host pins the one the silo reports and rebuilds the seed so cloud-init does
// not replace it. A host-local disk is left alone, and nothing of the disk is removed.
func (r *Runtime) SetGuestHostKey(ctx context.Context, id kri.ID, pub string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state(id)
	pub = strings.TrimSpace(pub)
	if !ok || pub == "" || pub == strings.TrimSpace(st.HostKey) {
		return nil
	}
	if st.RootDir == "" { // a host-local disk did not travel; its key stays
		return nil
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		return fmt.Errorf("guest host key: %w", err)
	}
	ip, err := netip.ParseAddr(st.IP)
	if err != nil {
		return err
	}
	n := NamesFor(id)
	if err := r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, "", pub)), 0o600); err != nil {
		return err
	}
	if err := r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(id, pub)), 0o600); err != nil {
		return err
	}
	if err := r.Host.WriteFile(n.Dir+"/network-config", []byte(NetworkConfig(st.MAC, ip, id.Namespace)), 0o600); err != nil {
		return err
	}
	if err := r.run(ctx, "cloud-localds", "--network-config="+n.Dir+"/network-config", n.Dir+"/seed.img", n.Dir+"/user-data", n.Dir+"/meta-data"); err != nil {
		return err
	}
	if err := r.run(ctx, "rm", "-f", n.Dir+"/user-data"); err != nil {
		return err
	}
	if err := r.run(ctx, "chown", VMMUser+":"+VMMUser, n.Dir+"/seed.img"); err != nil {
		return err
	}
	st.HostKey = pub
	return r.saveState(st)
}

// Start implements kri.Runtime.
func (r *Runtime) Start(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if st.Remake != nil {
		// Its reset was cut before its disk was made (kevasod stopped mid-convert, say): the disk
		// is partial. Made again, from the same image, before anything boots it.
		if err := r.finishRemake(ctx, id); err != nil {
			return fmt.Errorf("%s: its reset was cut short and its disk is not finished: %w (it doesn't start on a half-made disk)", id, err)
		}
		if st, ok = r.state(id); !ok || st.Remake != nil {
			return fmt.Errorf("%s: its reset could not be finished", id)
		}
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
	if !st.Started || !st.Made {
		st.Started, st.Made = true, true
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

// vmm says what systemd says of the VMM's unit, and whether a process of it may still run. An
// active unit runs. In every other state it decides from the processes (review-batch3 D): the
// unit's main process and its control group as systemd reports them, and the VMM itself, found
// by its API socket on its command line (a cgroup.procs that isn't there may be a cgroup removed,
// or cgroups mounted elsewhere on this host). Any of them there, or any of them that can't be
// told (systemctl show failing or not naming the main process of a unit that isn't stopped, a
// cgroup that can't be read, pgrep failing), and it may run: the fences take "not up" for
// stopped. The VMM's lock on its silo (LockFile) held is proof it runs, whatever the rest says;
// a MainPID counts only for a process that may be the VMM (mayBeVMM). A unit wedged in another state (deactivating, activating, reloading, maintenance)
// with none of them is cleaned up (SIGKILL to the unit's nothing, reset-failed), so the silo can
// move on: stopped, reset, started again or deleted.
func (r *Runtime) vmm(ctx context.Context, n Names) (state string, up bool) {
	state = r.active(ctx, n.Unit)
	stopped := state == "inactive" || state == "failed" || state == ""
	if state == "active" {
		return state, true
	}
	out, err := r.Host.Run(ctx, "systemctl", "show", "--property=MainPID,ControlGroup", n.Unit)
	if err != nil {
		return state, true // can't say: not gone
	}
	named := false
	for l := range strings.Lines(string(out)) {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch {
		case k == "MainPID":
			named = true
			if v != "" && v != "0" && r.mayBeVMM(v, n) {
				return state, true
			}
		case k == "ControlGroup" && v != "":
			procs, err := r.Host.ReadFile("/sys/fs/cgroup" + v + "/cgroup.procs")
			if (err != nil && !errors.Is(err, os.ErrNotExist)) || len(bytes.TrimSpace(procs)) > 0 {
				return state, true
			}
		}
	}
	if !named && !stopped {
		return state, true // a unit on its way somewhere, its main process not said: can't tell
	}
	if r.diskLocked(ctx, n) || r.vmmProcess(ctx, n.Socket) {
		return state, true
	}
	if !stopped {
		// Wedged with nothing of it running: its stop job ends, the unit is put back to inactive.
		_, _ = r.Host.Run(ctx, "systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", n.Unit)
		_, _ = r.Host.Run(ctx, "systemctl", "reset-failed", n.Unit)
	}
	return state, false
}

// mayBeVMM says whether the process pid, the unit's MainPID as systemd still shows it, may be
// this silo's VMM (review-batch4 claim 3a): a failed or inactive unit can show an old MainPID
// whose number was since reused by an unrelated process, which then counted as the VMM for as
// long as it ran. Its command line must name this silo's API socket (the VMM's, under its lock
// as the unit starts it); a process that is gone isn't it; one that can't be read may be.
func (r *Runtime) mayBeVMM(pid string, n Names) bool {
	b, err := r.Host.ReadFile("/proc/" + pid + "/cmdline")
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true // can't say
	}
	return bytes.Contains(b, []byte("--api-socket\x00"+n.Socket+"\x00"))
}

// LockFile is the lock a VMM holds on its silo for its whole life (review-batch4 claim 3b): the
// unit starts it under flock --no-fork, so the lock is the VMM's own open file, whatever its
// command line or cgroup look like, and a second VMM of the silo can never start while one runs.
func LockFile(n Names) string { return n.Dir + "/vmm.lock" }

// lockConflict is flock's exit code when the lock is held (-E).
const lockConflict = 75

// diskLocked says whether something holds the silo's VMM lock (a VMM runs, whatever else
// says), or that can't be told. Taking it for an instant is the probe: a VMM's unit waits a few
// seconds for it (UnitFor), so a probe never makes a start fail.
func (r *Runtime) diskLocked(ctx context.Context, n Names) bool {
	_, err := r.Host.Run(ctx, "flock", "-n", "-E", strconv.Itoa(lockConflict), LockFile(n), "true")
	if err == nil {
		return false
	}
	return true // held (exit 75), or flock couldn't say
}

// vmmProcess says whether a process runs with the VMM's API socket on its command line (the VMM,
// or a call to it), or that can't be told.
func (r *Runtime) vmmProcess(ctx context.Context, socket string) bool {
	out, err := r.Host.Run(ctx, "pgrep", "-f", "--", "--api-socket "+socket)
	if len(bytes.TrimSpace(out)) > 0 {
		return true
	}
	var ee *exec.ExitError
	if err == nil || errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false // pgrep: nothing matches
	}
	return true // pgrep didn't answer: can't say
}

// gone confirms the VMM is gone after a stop or a kill.
func (r *Runtime) gone(ctx context.Context, id kri.ID, how string) error {
	if state, up := r.vmm(ctx, NamesFor(id)); up {
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
	return r.deleteLockedRoot(ctx, id, true)
}

// deleteLockedRoot removes what the silo owns. dropRoot is false for a Create step that
// failed before this Create made the root LV: that volume is not this Create's to remove.
func (r *Runtime) deleteLockedRoot(ctx context.Context, id kri.ID, dropRoot bool) error {
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
	if l.RootFile == "" && dropRoot { // a step-failure removes the root LV only if this Create made it
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
			if err := r.runPool(ctx, "lvremove", "-q", "-y", VG+"/"+lv); err != nil {
				return err
			}
		}
	}
	return r.Host.RemoveAll(n.Dir)
}

// HasHostStorage implements kri.HostStorage. True when this host holds a root LV or any volume
// LV for id (a name kv-…-). applyLayout never removes a volume LV, so one taken out of the spec
// is still here until a delete of the silo removes it.
func (r *Runtime) HasHostStorage(ctx context.Context, id kri.ID) (bool, error) {
	n := NamesFor(id)
	out, err := r.Host.Run(ctx, "lvs", "--noheadings", "-o", "lv_name", VG)
	if err != nil { // a failed list is not "no disk"
		return false, fmt.Errorf("%s: logical volumes in %s could not be listed (%w): not treating this copy as without a disk", id, VG, err)
	}
	for _, f := range strings.Fields(string(out)) {
		if f == n.LV || strings.HasPrefix(f, n.LV+"-") { // root LV, or a volume LV kept after it left the spec
			return true, nil
		}
	}
	return false, nil
}

// rootDisk makes the silo's root disk from its image: a thin LV, or an image file on a mount
// class's folder. An image file already there is the silo's disk come from another host: it's
// kept, unless fresh (a reset) asks for a new one.
// rootDisk reports whether it made the root LV. made is true only after lvcreate succeeded,
// including when a later step of the disk fails: the caller may then remove that LV.
func (r *Runtime) rootDisk(ctx context.Context, n Names, l Layout, img string, size int64, fresh bool) (made bool, err error) {
	if _, err := r.imageFormat(img, size); err != nil {
		return false, err
	}
	if l.RootFile == "" {
		present, err := r.lvExists(ctx, n.LV)
		if err != nil { // a failed lvs is never "no volume"
			return false, fmt.Errorf("root volume %s/%s could not be checked (%w): not removing it", VG, n.LV, err)
		}
		if present {
			if !fresh {
				return false, fmt.Errorf("root volume %s/%s is there already: only a reset makes it afresh", VG, n.LV)
			}
			if err := r.runPool(ctx, "lvremove", "-q", "-y", VG+"/"+n.LV); err != nil {
				still, serr := r.lvExists(ctx, n.LV)
				if serr != nil || still {
					return false, fmt.Errorf("%w: %v", errRootKept, err)
				}
				return false, err
			}
		}
		if err := r.runPool(ctx, "lvcreate", "-q", "-T", VG+"/"+ThinPool, "-V", strconv.FormatInt(size>>20, 10)+"m", "-n", n.LV); err != nil {
			return false, err
		}
		if err := r.run(ctx, "qemu-img", "convert", "-n", "--target-is-zero", "-O", "raw", img, "/dev/"+VG+"/"+n.LV); err != nil {
			return true, err // this Create made the LV
		}
		return true, nil
	}
	if err := r.mustBeMounted(ctx, filepath.Dir(l.RootFile)); err != nil { // a root disk is written only on the volume's mount
		return false, err
	}
	_, probeErr := r.Host.Run(ctx, "test", "-e", l.RootFile)
	missing, err := probeMissing(probeErr)
	if err != nil {
		return false, fmt.Errorf("root disk %s could not be checked (%w): not writing it", l.RootFile, err)
	}
	if !missing && !fresh {
		return false, nil // moved here with its data
	}
	tmp := l.RootFile + ".new"
	for _, c := range RootFilePlan(img, tmp, l.RootFile, size) {
		if err := r.run(ctx, c[0], c[1:]...); err != nil {
			_ = r.Host.RemoveAll(tmp)
			if _, terr := r.Host.Run(ctx, "test", "-e", l.RootFile); terr == nil {
				return false, fmt.Errorf("%w: %v", errRootKept, err) // written beside it, put in place last
			}
			return false, err
		}
	}
	return false, nil
}

// probeMissing says whether test -e found the path absent. Exit 1 is absent. Any other
// failure is not: the path may be there, and nothing is written over it.
func probeMissing(err error) (bool, error) {
	code, ok := commandExit(err)
	switch {
	case ok && code == 0:
		return false, nil
	case ok && code == 1:
		return true, nil
	default:
		if err == nil {
			err = fmt.Errorf("exit %d", code)
		}
		return false, err
	}
}

// commandExit is a command's exit status. The real host returns exec.ExitError; tests say "exit N".
func commandExit(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	var n int
	if _, scanErr := fmt.Sscanf(err.Error(), "exit %d", &n); scanErr == nil {
		return n, true
	}
	return 0, false
}

// errRootKept: making a root disk afresh failed before the old one was touched (its lvremove
// failed; the new image file never put in place). K-112: a reset cut there removed nothing, so
// its mark goes and the disk is kept as it was: the next reset is asked for again, through its
// gate, never finished at a start with no one asked.
var errRootKept = errors.New("the root disk was kept as it was")

// RootFilePlan makes a root disk image file from an image: written next to it, grown to the disk's
// size (never shrunk), made the VMM's alone (qemu-img leaves it world-readable: the whole disk),
// then put in place, so a half-written image is never booted.
func RootFilePlan(img, tmp, file string, size int64) [][]string {
	return [][]string{
		{"rm", "-f", tmp},
		{"truncate", "-s", strconv.FormatInt(size, 10), tmp},
		{"qemu-img", "convert", "-n", "--target-is-zero", "-O", "raw", img, tmp},
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
		if _, up := r.vmm(ctx, NamesFor(id)); up {
			return kri.Status{State: kri.Running, Message: err.Error()}, nil
		}
		return kri.Status{State: kri.Failed, Message: err.Error() + ": its VMM doesn't run; delete the silo, or restore the file, to go on"}, nil
	}
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	if !st.Started && !st.Made && !r.made(id) {
		// Half-made (kevasod killed in Create, before the unit): absent, so it's created again
		// (Create redoes it); never started, so there's no disk of a running silo to keep.
		return kri.Status{State: kri.Absent}, nil
	}
	switch state, up := r.vmm(ctx, NamesFor(id)); {
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

// Unreadable names the state files List skips because they can't be read or parsed (K-105): the
// VM behind one may still run (Status and Kill find its VMM by its unit), so the agent lists them
// on the Host.
func (r *Runtime) Unreadable(context.Context) []string {
	paths, _ := r.Host.Glob(SilosDir + "/*/silo.json")
	var out []string
	for _, p := range paths {
		b, err := r.Host.ReadFile(p)
		var s State
		if err == nil {
			err = json.Unmarshal(b, &s)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			out = append(out, p)
		}
	}
	return out
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
	ctx, stop := r.whileUp(ctx, id) // a VMM that exits ends the wait for its guest, and the command
	defer stop()
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
			return -1, fmt.Errorf("ssh to %s: %w (last: %v)", id, context.Cause(ctx), err)
		case <-time.After(2 * time.Second):
		}
	}
	defer func() { _ = c.Close() }()
	code, err := runGuest(ctx, c, req)
	if err != nil && errors.Is(context.Cause(ctx), errVMMGone) {
		err = context.Cause(ctx)
	}
	return code, err
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
			// The sweep, bounded: a guest that is gone never answers it (closing c, by the caller,
			// ends it then).
			swept := make(chan struct{})
			go func() {
				defer close(swept)
				if sw, err := c.NewSession(); err == nil {
					_ = sw.Run("sh -c " + shellQuote([]string{hostexec.SweepScript}) + " sh " + marker)
					_ = sw.Close()
				}
			}()
			select {
			case <-swept:
			case <-time.After(sweepWait):
			}
			return -1, ctx.Err()
		}
	}
}

// sweepWait bounds the sweep after an Exec ends early.
const sweepWait = 10 * time.Second

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

// defaultDiskBytes is the root disk a silo gets when disk.size is empty.
const defaultDiskBytes int64 = 20 << 30

// diskBytesOrDefault is that disk: the size asked for, or the default when none was given.
// Zero is the default disk. It is never an uncapped fetch.
func diskBytesOrDefault(n int64) int64 {
	if n <= 0 {
		return defaultDiskBytes
	}
	return n
}

// image is the local file of an image: a built-in name's (fetched at install), or an Image
// version's disk (URL#sha256=HEX: fetched once, checked against its hash).
func (r *Runtime) image(ctx context.Context, image string, diskBytes int64) (string, error) {
	url, sum, ok := kri.ParseDiskImage(image)
	if !ok {
		return imagePath(image, r.Arch)
	}
	dst := filepath.Join(ImagesDir, "sha256-"+sum+".img")
	// The body is capped at the disk this silo will get. No disk.size (zero) is the default
	// disk, never an uncapped fetch. An address the disk must not be fetched from is refused too.
	if err := Fetch(ctx, r.Host, Asset{URL: url, SHA256: sum, File: filepath.Base(dst), MaxBytes: diskBytesOrDefault(diskBytes)}, dst, 0o600); err != nil {
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
	img, err := r.image(ctx, spec.Image, spec.DiskBytes)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.state(spec.ID)
	if !ok {
		return fmt.Errorf("%s: %w", spec.ID, kri.ErrNotFound)
	}
	if _, err := netip.ParseAddr(st.IP); err != nil {
		return err
	}
	n := NamesFor(spec.ID)
	disk := diskBytesOrDefault(spec.DiskBytes)
	mem := spec.Memory
	if mem <= 0 {
		mem = 1 << 30
	}
	cpus := spec.CPU
	if cpus <= 0 {
		cpus = 1
	}
	old := st
	st.CPUs, st.MemMiB, st.Volumes, st.RootDir = cpus, mem>>20, spec.Volumes, spec.DiskHostPath
	for _, c := range StopPlan(n, old.layout()) {
		_, _ = r.Host.Run(ctx, c[0], c[1:]...)
	}
	if err := r.gone(ctx, spec.ID, "a stop"); err != nil { // its disk is made afresh next: never under a VMM
		return fmt.Errorf("reset %s: %w", spec.ID, err)
	}
	if gate != nil {
		if err := gate(ctx); err != nil {
			return fmt.Errorf("reset %s: %w", spec.ID, err)
		}
	}
	// From here on its disk is destroyed: the intent is on disk first, so a cut reset is
	// finished (finishRemake), never booted half-made.
	st.Remake = &Remake{Image: spec.Image, DiskBytes: disk, OldVolumes: old.Volumes, OldRootDir: old.RootDir}
	if err := r.saveState(st); err != nil {
		return fmt.Errorf("reset %s: %w", spec.ID, err)
	}
	if err := r.remakeLocked(ctx, st, img); err != nil {
		if errors.Is(err, errRootKept) {
			if serr := r.saveState(old); serr != nil { // nothing removed: as it was, with no mark
				err = errors.Join(err, serr)
			}
		}
		return fmt.Errorf("reset %s: %w", spec.ID, err)
	}
	return nil
}

// finishRemake makes afresh the root disk of a silo whose reset was cut (State.Remake), from the
// same image, and clears the mark.
func (r *Runtime) finishRemake(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok || st.Remake == nil {
		return nil
	}
	img, err := r.image(ctx, st.Remake.Image, st.Remake.DiskBytes)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok = r.state(id); !ok || st.Remake == nil {
		return nil
	}
	if _, up := r.vmm(ctx, NamesFor(id)); up {
		return errors.New("its VMM runs") // never under a VMM (not reached: Remake means it was gone)
	}
	err = r.remakeLocked(ctx, st, img)
	if errors.Is(err, errRootKept) {
		// Nothing of its disk was removed (K-112): the mark goes, the old disk stays, and it
		// starts as it was; a reset still asked for comes again through its gate.
		st.Remake, st.Volumes, st.RootDir = nil, st.Remake.OldVolumes, st.Remake.OldRootDir
		return r.saveState(st)
	}
	return err
}

// remakeLocked does a reset's destructive steps, each one safe to do again: the root disk made
// afresh from img, the seed rebuilt with a new guest host key, the layout applied. Only after
// the last is the mark cleared (with r.mu held).
func (r *Runtime) remakeLocked(ctx context.Context, st State, img string) error {
	n := NamesFor(st.ID)
	ip, err := netip.ParseAddr(st.IP)
	if err != nil {
		return err
	}
	hostPub, hostPriv, err := newHostKey()
	if err != nil {
		return err
	}
	rm := st.Remake
	oldLayout := LayoutFor(n, rm.OldVolumes, rm.OldRootDir)
	layout := st.layout()
	steps := []func() error{
		func() error {
			_, err := r.rootDisk(ctx, n, layout, img, rm.DiskBytes, true)
			return err
		},
		func() error {
			return r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, hostPriv, hostPub)), 0o600)
		},
		func() error { return r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(st.ID, hostPub)), 0o600) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/network-config", []byte(NetworkConfig(st.MAC, ip, st.ID.Namespace)), 0o600)
		},
		func() error {
			return r.run(ctx, "cloud-localds", "--network-config="+n.Dir+"/network-config", n.Dir+"/seed.img", n.Dir+"/user-data", n.Dir+"/meta-data")
		},
		func() error { return r.run(ctx, "rm", "-f", n.Dir+"/user-data") },
		func() error { return r.run(ctx, "chown", VMMUser+":"+VMMUser, n.Dir+"/seed.img") },
		func() error { return r.applyLayout(ctx, st, oldLayout, layout) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	st.HostKey, st.Started, st.Made, st.Remake = hostPub, false, true, nil
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

var (
	_ kri.Runtime            = (*Runtime)(nil)
	_ kri.GuestHostKeySource = (*Runtime)(nil)
	_ kri.GuestHostKeySetter = (*Runtime)(nil)
	_ kri.HostStorage        = (*Runtime)(nil)
)
