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

func (r *Runtime) saveState(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return r.Host.WriteFile(NamesFor(s.ID).Dir+"/silo.json", b, 0o600)
}

// Create implements kri.Runtime: disk from the image, cloud-init seed, TAP, VMM unit. Not started.
func (r *Runtime) Create(ctx context.Context, spec kri.Spec) error {
	if _, ok := r.state(spec.ID); ok {
		return nil
	}
	img, err := r.image(ctx, spec.Image) // before the lock: a first fetch takes a while
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.state(spec.ID); ok {
		return nil
	}
	n := NamesFor(spec.ID)
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

// waitFor waits for a virtiofsd's socket (it's up once it's there).
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
	return nil
}

func (r *Runtime) active(ctx context.Context, unit string) string {
	out, _ := r.Host.Run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(string(out))
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
// size (never shrunk), then put in place, so a half-written image is never booted.
func RootFilePlan(img, tmp, file string, size int64) [][]string {
	return [][]string{
		{"rm", "-f", tmp},
		{"qemu-img", "convert", "-O", "raw", img, tmp},
		{"qemu-img", "resize", "-f", "raw", tmp, strconv.FormatInt(size, 10)},
		{"mv", "-f", tmp, file},
	}
}

// Status implements kri.Runtime.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	st, ok := r.state(id)
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	switch r.active(ctx, NamesFor(id).Unit) {
	case "active", "activating":
		return kri.Status{State: kri.Running, Address: st.IP}, nil
	case "failed":
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
