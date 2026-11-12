package cloudhypervisor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"kevaso.com/core/builtin/kni"
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
var Packages = []string{"qemu-utils", "cloud-image-utils", "lvm2", "thin-provisioning-tools", "nftables", "iproute2", "iputils-arping"}

// StorageOptions say where silo disks live.
type StorageOptions struct {
	// LoopFile backs the volume group with a sparse file when the host has no VG "kevaso" yet
	// (development and test machines; production hosts get a real disk). Empty: require the VG.
	LoopFile string
	LoopSize string // e.g. 64G
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
			if _, err := r.Host.Run(ctx, "id", VMMUser); err == nil {
				return nil
			}
			return r.run(ctx, "useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--groups", "kvm", VMMUser)
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
	if err := r.run(ctx, "apt-get", "update", "-qq"); err != nil {
		return err
	}
	return r.run(ctx, "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-qq"}, missing...)...)
}

// NFT is the host's silo firewall with no silos yet (the worker rewrites it as silos come and
// go): see builtin/kni.
func NFT() string {
	return kni.Rules(kni.Host{Bridge: Bridge, Subnet: Network, Gateway: Gateway})
}

func (r *Runtime) setupNetwork(ctx context.Context) error { return SetupNetwork(ctx, r.Host) }

// SetupNetwork makes the silo bridge with the host's gateway address, turns on forwarding and loads
// the baseline firewall. Every runtime on the bridge (VMs, containers) needs it; it's idempotent.
func SetupNetwork(ctx context.Context, h Host) error {
	r := &Runtime{Host: h}
	if _, err := r.Host.Run(ctx, "ip", "link", "show", Bridge); err != nil {
		if err := r.run(ctx, "ip", "link", "add", Bridge, "type", "bridge"); err != nil {
			return err
		}
		if err := r.run(ctx, "ip", "addr", "add", Gateway.String()+"/24", "dev", Bridge); err != nil {
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
	if err := r.Host.WriteFile("/etc/kevaso-silos.nft", []byte(NFT()), 0o600); err != nil {
		return err
	}
	return r.run(ctx, "nft", "-f", "/etc/kevaso-silos.nft")
}

func (r *Runtime) setupStorage(ctx context.Context, o StorageOptions) error {
	if out, err := r.Host.Run(ctx, "lvs", "--noheadings", VG+"/"+ThinPool); err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return nil
	}
	if _, err := r.Host.Run(ctx, "vgs", VG); err != nil {
		if o.LoopFile == "" {
			return fmt.Errorf("volume group %q missing: create it on a disk, or allow a loop file for development", VG)
		}
		size := o.LoopSize
		if size == "" {
			size = "64G"
		}
		if err := r.run(ctx, "truncate", "-s", size, o.LoopFile); err != nil {
			return err
		}
		dev, err := r.Host.Run(ctx, "losetup", "--find", "--show", o.LoopFile)
		if err != nil {
			return fmt.Errorf("losetup: %w", err)
		}
		d := strings.TrimSpace(string(dev))
		if err := r.run(ctx, "pvcreate", "-q", d); err != nil {
			return err
		}
		if err := r.run(ctx, "vgcreate", "-q", VG, d); err != nil {
			return err
		}
	}
	if err := r.run(ctx, "lvcreate", "-q", "--type", "thin-pool", "-l", "90%FREE", "-n", ThinPool, VG); err != nil {
		return err
	}
	// A full pool fails writes fast instead of hanging guests (E012).
	return r.run(ctx, "lvchange", "-q", "--errorwhenfull", "y", VG+"/"+ThinPool)
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
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.CombinedOutput()
}

// WriteFile implements Host.
func (Local) WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

// ReadFile implements Host.
func (Local) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// RemoveAll implements Host.
func (Local) RemoveAll(path string) error { return os.RemoveAll(path) }

// Glob implements Host.
func (Local) Glob(pattern string) ([]string, error) { return filepath.Glob(pattern) }
