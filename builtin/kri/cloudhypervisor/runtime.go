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
	st := State{ID: spec.ID, IP: ip.String(), MAC: MAC(spec.ID), HostKey: hostPub}

	if err := r.run(ctx, "install", "-d", "-m", "0700", "-o", VMMUser, "-g", VMMUser, n.Dir); err != nil {
		return err
	}
	if err := r.saveState(st); err != nil { // first: from here on, Delete knows what to clean up
		return err
	}
	unlockIP()
	steps := []func() error{
		func() error {
			return r.run(ctx, "lvcreate", "-q", "-T", VG+"/"+ThinPool, "-V", strconv.FormatInt(disk>>20, 10)+"m", "-n", n.LV)
		},
		func() error {
			return r.run(ctx, "qemu-img", "convert", "-n", "--target-is-zero", "-O", "raw", img, "/dev/"+VG+"/"+n.LV)
		},
		func() error {
			return r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, hostPriv, hostPub)), 0o600)
		},
		func() error { return r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(spec.ID)), 0o600) },
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
		func() error {
			return r.Host.WriteFile("/etc/systemd/system/"+n.Unit, []byte(Unit(n, cpus, mem>>20, r.Firmware(), st.MAC)), 0o644)
		},
		func() error { return r.run(ctx, "systemctl", "daemon-reload") },
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
	if err := r.run(ctx, "ip", "link", "set", n.Tap, "up"); err != nil {
		return err
	}
	if err := r.run(ctx, "systemctl", "start", n.Unit); err != nil {
		return err
	}
	if !st.Started {
		st.Started = true
		return r.saveState(st)
	}
	return nil
}

// Stop implements kri.Runtime: ask the guest to power off, then stop the unit if it doesn't.
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	if _, ok := r.state(id); !ok {
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
	_, _ = r.Host.Run(ctx, "systemctl", "stop", n.Unit)
	_, _ = r.Host.Run(ctx, "systemctl", "reset-failed", n.Unit)
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

func (r *Runtime) deleteLocked(ctx context.Context, id kri.ID) error {
	if _, ok := r.state(id); !ok {
		return nil
	}
	n := NamesFor(id)
	_, _ = r.Host.Run(ctx, "systemctl", "stop", n.Unit)
	_, _ = r.Host.Run(ctx, "systemctl", "reset-failed", n.Unit)
	_ = r.Host.RemoveAll("/etc/systemd/system/" + n.Unit)
	_, _ = r.Host.Run(ctx, "systemctl", "daemon-reload")
	_, _ = r.Host.Run(ctx, "ip", "link", "del", n.Tap)
	if out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+n.LV); err == nil && len(bytes.TrimSpace(out)) > 0 {
		if err := r.run(ctx, "lvremove", "-q", "-y", VG+"/"+n.LV); err != nil {
			return err
		}
	}
	return r.Host.RemoveAll(n.Dir)
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

// Exec implements kri.Runtime: SSH to the guest over the bridge as the exec user (whose key only
// this host holds), with the guest's host key pinned, then `sudo -n -- argv`. It waits for the
// guest's SSH to come up (first boot).
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
		User:              GuestUser,
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
	sess, err := c.NewSession()
	if err != nil {
		return -1, err
	}
	defer func() { _ = sess.Close() }()
	sess.Stdin, sess.Stdout, sess.Stderr = req.Stdin, orDiscard(req.Stdout), orDiscard(req.Stderr)
	err = sess.Run("sudo -n -- " + shellQuote(req.Command))
	var exitErr *ssh.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exitErr):
		return exitErr.ExitStatus(), nil
	default:
		return -1, err
	}
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
	steps := []func() error{
		func() error { return r.run(ctx, "systemctl", "stop", n.Unit) },
		func() error {
			if out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+n.LV); err == nil && len(bytes.TrimSpace(out)) > 0 {
				return r.run(ctx, "lvremove", "-q", "-y", VG+"/"+n.LV)
			}
			return nil
		},
		func() error {
			return r.run(ctx, "lvcreate", "-q", "-T", VG+"/"+ThinPool, "-V", strconv.FormatInt(disk>>20, 10)+"m", "-n", n.LV)
		},
		func() error {
			return r.run(ctx, "qemu-img", "convert", "-n", "--target-is-zero", "-O", "raw", img, "/dev/"+VG+"/"+n.LV)
		},
		func() error {
			return r.Host.WriteFile(n.Dir+"/user-data", []byte(UserData(r.ExecPub, hostPriv, hostPub)), 0o600)
		},
		func() error { return r.Host.WriteFile(n.Dir+"/meta-data", []byte(MetaData(spec.ID)), 0o600) },
		func() error {
			return r.Host.WriteFile(n.Dir+"/network-config", []byte(NetworkConfig(st.MAC, ip, spec.ID.Namespace)), 0o600)
		},
		func() error {
			return r.run(ctx, "cloud-localds", "--network-config="+n.Dir+"/network-config", n.Dir+"/seed.img", n.Dir+"/user-data", n.Dir+"/meta-data")
		},
		func() error { return r.run(ctx, "rm", "-f", n.Dir+"/user-data") },
		func() error { return r.run(ctx, "chown", VMMUser+":"+VMMUser, n.Dir+"/seed.img") },
		func() error {
			return r.Host.WriteFile("/etc/systemd/system/"+n.Unit, []byte(Unit(n, cpus, mem>>20, r.Firmware(), st.MAC)), 0o644)
		},
		func() error { return r.run(ctx, "systemctl", "daemon-reload") },
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

// BrokerListen implements kri.Broker: a unix socket at the VM's Vsock_PORT, which only that VM's
// VMM can reach (it runs with only its own silo directory visible) and only that VM's guest uses.
func (r *Runtime) BrokerListen(id kri.ID, port uint32) (net.Listener, error) {
	if _, ok := r.state(id); !ok {
		return nil, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	path := fmt.Sprintf("%s_%d", NamesFor(id).Vsock, port)
	_ = r.Host.RemoveAll(path) // a stale socket from before a restart
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := r.run(context.Background(), "chown", VMMUser+":"+VMMUser, path); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

var (
	_ kri.Runtime = (*Runtime)(nil)
	_ kri.Broker  = (*Runtime)(nil)
)
