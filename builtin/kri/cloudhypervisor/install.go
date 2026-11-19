package cloudhypervisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/builtin/kri/hostpkg"
)

// Asset is a file to download, with its pinned digest.
type Asset struct {
	URL    string
	SHA256 string // hex; empty: checked against SumsURL instead
	File   string // name in its directory
	// SumsURL is a SHA256SUMS file to check against (for images whose "current" build changes).
	SumsURL string
}

// Version pins what the runtime installs (research E008, E036: v54.1 and edk2 ch-97eeb7b09).
const Version = "v54.1"

// Binaries per CPU: the VMM, its remote control, and the firmware.
var Binaries = map[string][]Asset{
	"x86_64": {
		{URL: "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/cloud-hypervisor-static",
			SHA256: "f9ffb9646783233d1f0fb09e77db1fca66499d1041e63bc011b90683c0d49933", File: "cloud-hypervisor"},
		{URL: "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/ch-remote-static",
			SHA256: "06c111b691ee085c0392e6d53f6600131e425e54669546dd0f2c40bdedc8e5ce", File: "ch-remote"},
		{URL: "https://github.com/cloud-hypervisor/edk2/releases/download/ch-97eeb7b09/CLOUDHV.fd",
			SHA256: "dc2fc8f0e43b96712d9fccc52a3a590769606412b3e1bc911d217addd3bef624", File: "CLOUDHV.fd"},
	},
	"aarch64": {
		{URL: "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/cloud-hypervisor-static-aarch64",
			SHA256: "96ef17679a4a75be8eefa1956dd645a57f7974ec50565090ea9298f9bbb761ad", File: "cloud-hypervisor"},
		{URL: "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.1/ch-remote-static-aarch64",
			SHA256: "482eebdb3bc13eb35bded9429cc6063c18c31a7d8f98b9a21d9ebdaafc01485c", File: "ch-remote"},
		{URL: "https://github.com/cloud-hypervisor/edk2/releases/download/ch-97eeb7b09/CLOUDHV_EFI.fd",
			SHA256: "13cf4eddc44f3fac4e223b54bcf958de99539297fee8b61cca2605ab5b5009fb", File: "CLOUDHV_EFI.fd"},
	},
}

// Images per name and CPU (checked against Ubuntu's SHA256SUMS over HTTPS).
var Images = map[string]map[string]Asset{
	"ubuntu-24.04": {
		"x86_64": {URL: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
			SumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS", File: "ubuntu-24.04-x86_64.img"},
		"aarch64": {URL: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
			SumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS", File: "ubuntu-24.04-aarch64.img"},
	},
}

// Packages the host needs (Ubuntu/Debian names).
var Packages = []string{"qemu-utils", "cloud-image-utils", "lvm2", "thin-provisioning-tools", "nftables", "iproute2", "iputils-arping", "virtiofsd"}

// StorageOptions say where silo disks live.
type StorageOptions struct {
	// LoopFile backs the volume group with a sparse file when the host has no VG "kevaso" yet
	// (development and test machines; production hosts get a real disk). Empty: require the VG.
	LoopFile string
	LoopSize string // e.g. 64G
	// Device is a whole, empty disk the volume group is made on when there's none yet
	// (/dev/nvme1n1): refused unless it has no partitions, no signatures, no mounts and no holders.
	Device string
}

// DiskEmpty decides whether a disk may become the volume group's: lsblk is
// "lsblk -nr -o NAME,TYPE,MOUNTPOINT DEV" (one line: the disk itself, unmounted), wipefs is
// "wipefs -n DEV" (nothing: no filesystem, RAID, LVM or partition-table signature). Pure.
func DiskEmpty(dev, lsblk, wipefs string) error {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(lsblk), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	switch {
	case len(lines) == 0:
		return fmt.Errorf("%s: no such disk", dev)
	case len(lines) > 1:
		return fmt.Errorf("%s has partitions or holders (%s): Kevaso takes a whole, empty disk only", dev, strings.Join(lines[1:], "; "))
	}
	f := strings.Fields(lines[0])
	if len(f) < 2 || f[1] != "disk" {
		return fmt.Errorf("%s is %q, not a whole disk", dev, lines[0])
	}
	if len(f) > 2 {
		return fmt.Errorf("%s is mounted on %s", dev, f[2])
	}
	if strings.TrimSpace(wipefs) != "" {
		return fmt.Errorf("%s isn't empty (wipefs found: %s): Kevaso never writes over a disk with anything on it", dev, strings.Join(strings.Fields(wipefs), " "))
	}
	return nil
}

// Install prepares the host: packages, the VMM user, pinned binaries and the image, the silo
// bridge with NAT and default-deny between silos, and the thin pool. Safe to run again. progress,
// if set, hears each step as it starts ("3/7 binaries").
func (r *Runtime) Install(ctx context.Context, store StorageOptions, progress func(string)) error {
	steps := []struct {
		what string
		fn   func() error
	}{
		{"packages (lvm2, nftables, qemu-utils, genisoimage)", func() error { return r.installPackages(ctx) }},
		{"vmm user", func() error {
			if _, err := r.Host.Run(ctx, "id", VMMUser); err != nil {
				if err := r.run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--groups", "kvm", VMMUser); err != nil {
					return err
				}
			}
			if _, err := r.Host.Run(ctx, "id", ImgUser); err == nil {
				return nil
			}
			return r.run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", ImgUser)
		}},
		{"directories", func() error {
			if err := r.run(ctx, "install", "-d", "-m", "0755", BinDir, SilosDir); err != nil {
				return err
			}
			return r.run(ctx, "install", "-d", "-m", "0700", ImagesDir)
		}},
		{"binaries (Cloud Hypervisor " + Version + " + firmware)", func() error {
			assets, ok := Binaries[r.Arch]
			if !ok {
				return fmt.Errorf("no Cloud Hypervisor build for %s", r.Arch)
			}
			for _, a := range assets {
				if err := Fetch(ctx, r.Host, a, filepath.Join(BinDir, a.File), 0o755); err != nil {
					return err
				}
			}
			return nil
		}},
		{"image (Ubuntu 24.04, ~600 MB, first time only)", func() error {
			a := Images["ubuntu-24.04"][r.Arch]
			return Fetch(ctx, r.Host, a, filepath.Join(ImagesDir, a.File), 0o600)
		}},
		{"network (bridge, NAT, silo isolation)", func() error { return r.setupNetwork(ctx) }},
		{"storage (thin LVM pool)", func() error { return r.setupStorage(ctx, store) }},
	}
	for i, s := range steps {
		if progress != nil {
			progress(fmt.Sprintf("%d/%d %s", i+1, len(steps), s.what))
		}
		if err := s.fn(); err != nil {
			return fmt.Errorf("install %s: %w", s.what, err)
		}
	}
	return nil
}

func (r *Runtime) installPackages(ctx context.Context) error {
	var missing []string
	for _, p := range Packages {
		if out, err := r.Host.Run(ctx, "dpkg-query", "-W", "-f=${Status}", p); err != nil || !strings.Contains(string(out), "install ok installed") {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	defer hostpkg.Lock()()
	if err := r.run(ctx, "sh", "-c", hostpkg.Update); err != nil {
		return err
	}
	// What it installs is recorded as Kevaso's (K-113): only that is purged by a reset.
	return r.run(ctx, "sh", append([]string{"-c", hostpkg.Recording("DEBIAN_FRONTEND=noninteractive apt-get -o " + hostpkg.LockTimeout + " install -y -qq \"$@\""), "sh"}, missing...)...)
}

// NFT is the host's silo firewall with no silos yet (the worker rewrites it as silos come and
// go): see builtin/kni.
func NFT() string {
	return kni.Rules(kni.Host{Bridge: Bridge, Subnet: Network, Gateway: Gateway})
}

func (r *Runtime) setupNetwork(ctx context.Context) error { return SetupNetwork(ctx, r.Host) }

// bridgeMu serializes SetupNetwork in this process. Cloud-hypervisor and the container runtime both
// set up kvbr0 at boot; a second process still races in the kernel, and that path is below.
var bridgeMu sync.Mutex

// SetupNetwork makes the silo bridge with the host's gateway address, turns on forwarding and loads
// the baseline firewall. Every runtime on the bridge (VMs, containers) needs it; it's idempotent.
// The second ip link add answers "File exists" when the other runtime created kvbr0 first. Setup
// continues when that link is a bridge. A device of some other kind is left alone and reported.
func SetupNetwork(ctx context.Context, h Host) error {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	r := &Runtime{Host: h}
	if _, err := r.Host.Run(ctx, "ip", "link", "show", Bridge); err != nil {
		if err := r.run(ctx, "ip", "link", "add", Bridge, "type", "bridge"); err != nil {
			if !fileExists(err) {
				return err
			}
			// The other runtime won the create. Use the link only once it is a bridge.
			if err := confirmBridge(ctx, r); err != nil {
				return err
			}
		}
		// The address add races the same way: the winner may have added the gateway already.
		if err := r.run(ctx, "ip", "addr", "add", Gateway.String()+"/24", "dev", Bridge); err != nil && !fileExists(err) {
			return err
		}
	}
	if err := r.run(ctx, "ip", "link", "set", Bridge, "up"); err != nil {
		return err
	}
	if err := r.run(ctx, "sysctl", "-qw", "net.ipv4.ip_forward=1"); err != nil {
		return err
	}
	_, _ = r.Host.Run(ctx, "modprobe", "nf_conntrack_bridge") // bridge conntrack, for the silo rules
	// The baseline only where there's no ruleset (a boot): a live one is the silos' whole
	// firewall, kept by the worker, and replacing it here (a kevasod restart, an Install retried)
	// dropped their ports and anti-spoofing until the worker's next apply.
	if _, err := r.Host.Run(ctx, "nft", "list", "table", "inet", "kevaso"); err == nil {
		return nil
	}
	if err := r.Host.WriteFile("/etc/kevaso-silos.nft", []byte(NFT()), 0o600); err != nil {
		return err
	}
	return r.run(ctx, "nft", "-f", "/etc/kevaso-silos.nft")
}

// fileExists reports ip(8)'s "RTNETLINK answers: File exists": the link or address is already there.
func fileExists(err error) bool {
	return err != nil && strings.Contains(err.Error(), "File exists")
}

// confirmBridge checks the link ip link add refused to create. ip -d link show names a bridge
// device with a "bridge" detail field ("bridge_slave" is a port of one, and is not). Anything else
// keeps the name and fails setup.
func confirmBridge(ctx context.Context, r *Runtime) error {
	out, err := r.Host.Run(ctx, "ip", "-d", "link", "show", Bridge)
	if err != nil {
		return fmt.Errorf("ip -d link show %s: %w: %s", Bridge, err, strings.TrimSpace(string(out)))
	}
	if !slices.Contains(strings.Fields(string(out)), "bridge") {
		return fmt.Errorf("%s exists but is not a bridge", Bridge)
	}
	return nil
}

func (r *Runtime) setupStorage(ctx context.Context, o StorageOptions) error {
	if r.poolReady(ctx) {
		return nil
	}
	_, vgErr := r.Host.Run(ctx, "vgs", VG)
	if vgErr != nil && o.LoopFile != "" {
		// A loop file from an earlier start: a reboot detaches it, and the volume group on it is
		// gone until it's attached again. Attach it (to the device it's on already, if any) and
		// let LVM find the group: never truncate it or write a new physical volume over it.
		if _, err := r.Host.Run(ctx, "test", "-e", o.LoopFile); err == nil {
			if _, err := r.loopDevice(ctx, o.LoopFile); err != nil {
				return err
			}
			_, _ = r.Host.Run(ctx, "pvscan", "--cache")
			if _, vgErr = r.Host.Run(ctx, "vgs", VG); vgErr != nil {
				return fmt.Errorf("%s exists but holds no volume group %q: Kevaso won't write over it (move it away to start with an empty one)", o.LoopFile, VG)
			}
		}
	}
	if vgErr != nil && o.Device != "" {
		if o.LoopFile != "" {
			return errors.New("a storage device or a loop file, not both")
		}
		if !strings.HasPrefix(o.Device, "/dev/") {
			return fmt.Errorf("storage device %q: give its /dev path", o.Device)
		}
		lsblk, err := r.Host.Run(ctx, "lsblk", "-nr", "-o", "NAME,TYPE,MOUNTPOINT", o.Device)
		if err != nil {
			return fmt.Errorf("storage device %s: %w", o.Device, err)
		}
		wipe, err := r.Host.Run(ctx, "wipefs", "-n", o.Device)
		if err != nil {
			return fmt.Errorf("storage device %s: %w", o.Device, err)
		}
		if err := DiskEmpty(o.Device, string(lsblk), string(wipe)); err != nil {
			return err
		}
		if err := r.run(ctx, "pvcreate", "-q", o.Device); err != nil {
			return err
		}
		if err := r.run(ctx, "vgcreate", "-q", VG, o.Device); err != nil {
			return err
		}
		vgErr = nil
	}
	if vgErr != nil {
		if o.LoopFile == "" {
			return fmt.Errorf("volume group %q missing: name an empty disk for it (--storage-device), create it yourself, or allow a loop file for development", VG)
		}
		size := o.LoopSize
		if size == "" {
			size = "64G"
		}
		if err := r.run(ctx, "truncate", "-s", size, o.LoopFile); err != nil {
			return err
		}
		d, err := r.loopDevice(ctx, o.LoopFile)
		if err != nil {
			return err
		}
		if err := r.run(ctx, "pvcreate", "-q", d); err != nil {
			return err
		}
		if err := r.run(ctx, "vgcreate", "-q", VG, d); err != nil {
			return err
		}
	}
	// Active (after a boot, the group is found but its volumes may not be).
	if err := r.run(ctx, "vgchange", "-q", "-ay", VG); err != nil {
		return err
	}
	if r.poolReady(ctx) {
		return nil
	}
	if err := r.runPool(ctx, "lvcreate", "-q", "--type", "thin-pool", "-l", "90%FREE", "-n", ThinPool, VG); err != nil {
		return err
	}
	// A full pool fails writes fast instead of hanging guests (E012).
	return r.runPool(ctx, "lvchange", "-q", "--errorwhenfull", "y", VG+"/"+ThinPool)
}

// PoolSize is the thin pool's size and what the thin volumes in it promise already, in bytes:
// what a host offers for local volumes (§0.8, refused at creation past it), not what's written.
func (r *Runtime) PoolSize(ctx context.Context) (size, provisioned int64, err error) {
	out, err := r.Host.Run(ctx, "lvs", "--noheadings", "--units", "b", "--nosuffix", "-o", "lv_name,lv_size,pool_lv", VG)
	if err != nil {
		return 0, 0, fmt.Errorf("lvs %s: %w", VG, err)
	}
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("lvs %s: size %q", VG, f[1])
		}
		switch {
		case f[0] == ThinPool:
			size, found = n, true
		case len(f) == 3 && f[2] == ThinPool:
			provisioned += n
		}
	}
	if !found {
		return 0, 0, fmt.Errorf("no thin pool %s/%s", VG, ThinPool)
	}
	return size, provisioned, nil
}

// fits refuses a new thin volume of size bytes when the pool hasn't that much left unpromised
// (§0.8: refused at creation, with the numbers; a pool is never promised more than its size).
func (r *Runtime) fits(ctx context.Context, what string, size int64) error {
	pool, promised, err := r.PoolSize(ctx)
	if err != nil {
		return err
	}
	if left := pool - promised; size > left {
		return fmt.Errorf("%s needs %s: this host's storage (%s/%s) is %s, %s of it promised to other disks already (%s left)",
			what, gib(size), VG, ThinPool, gib(pool), gib(promised), gib(max(left, 0)))
	}
	return nil
}

// gib says a size in GiB, the way silo specs write them (40Gi, 1.5Gi).
func gib(b int64) string {
	return strconv.FormatFloat(math.Round(float64(b)/(1<<30)*10)/10, 'f', -1, 64) + "Gi"
}

// poolReady says whether the thin pool exists.
func (r *Runtime) poolReady(ctx context.Context) bool {
	out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+ThinPool)
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}

// loopDevice is the loop device file is attached to, attaching it when it isn't.
func (r *Runtime) loopDevice(ctx context.Context, file string) (string, error) {
	if out, err := r.Host.Run(ctx, "losetup", "-n", "-O", "NAME", "-j", file); err == nil {
		if f := strings.Fields(string(out)); len(f) > 0 {
			return f[0], nil
		}
	}
	dev, err := r.Host.Run(ctx, "losetup", "--find", "--show", file)
	if err != nil {
		return "", fmt.Errorf("losetup: %w", err)
	}
	return strings.TrimSpace(string(dev)), nil
}

// Fetch downloads an asset to dst, verifying its digest; an existing file with the right digest
// is kept. The download goes to a temp file and is renamed only once verified.
func Fetch(ctx context.Context, h Host, a Asset, dst string, mode os.FileMode) error {
	want := a.SHA256
	if want == "" && a.SumsURL != "" {
		sums, err := httpGet(ctx, a.SumsURL)
		if err != nil {
			return err
		}
		if want = digestFromSums(sums, filepath.Base(a.URL)); want == "" {
			return fmt.Errorf("%s not listed in %s", filepath.Base(a.URL), a.SumsURL)
		}
	}
	if want == "" {
		return fmt.Errorf("%s: no digest to verify against", a.URL)
	}
	if got, err := fileSHA256(h, dst); err == nil && got == want {
		return nil
	}
	tmp := dst + ".download"
	if err := download(ctx, a.URL, tmp); err != nil {
		return err
	}
	got, err := fileSHA256(h, tmp)
	if err != nil {
		return err
	}
	if got != want {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: digest %s, want %s", a.URL, got, want)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func digestFromSums(sums []byte, file string) string {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			return f[0]
		}
	}
	return ""
}

func fileSHA256(_ Host, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Local is the real Host: commands via os/exec, files via os.
type Local struct{}

// Run implements Host.
func (Local) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if err := hostexec.SetCommandDir(cmd); err != nil {
		return nil, err
	}
	cmd.WaitDelay = hostexec.WaitDelay // a process it leaves with the output open doesn't hold the caller
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrWaitDelay) && ctx.Err() == nil && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil // it exited 0; what it left behind holds its output (that output is cut)
	}
	return out, err
}

// WriteFile implements Host: atomically (a temporary file, synced, renamed over it), so a kill or
// a crash leaves the old file or the new one. A truncated silo.json read as no silo, and Create
// then put a fresh root disk over the old one.
func (Local) WriteFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// ReadFile implements Host.
func (Local) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// RemoveAll implements Host.
func (Local) RemoveAll(path string) error { return os.RemoveAll(path) }

// Glob implements Host.
func (Local) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
