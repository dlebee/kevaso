package openshell

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"kevaso.com/core/builtin/kri/hostpkg"
)

// Install readies the host: the pinned OpenShell package (checksum verified here), Docker for the
// container driver, /dev/kvm for the VM driver. The package's own per-user gateway service stays
// off: Kevaso runs its own, locked down (E028).
func (r *Runtime) Install(ctx context.Context, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	if r.Driver == DriverVM {
		if _, err := os.Stat("/dev/kvm"); err != nil {
			return ErrNoKVM
		}
	}
	if r.Driver == DriverDocker {
		if err := r.run(ctx, "sh", "-c", "command -v docker"); err != nil {
			progress("installing Docker (docker.io)")
			unlock := hostpkg.Lock()
			err := r.run(ctx, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get -o "+hostpkg.LockTimeout+" install -y -q docker.io")
			unlock()
			if err != nil {
				return err
			}
		}
		if err := r.run(ctx, "systemctl", "enable", "--now", "docker"); err != nil {
			return err
		}
	}
	// Both runtimes (VM and container drivers) install the same package, at the same time.
	installMu.Lock()
	defer installMu.Unlock()
	var v bytes.Buffer
	_, _ = r.Host.Run(ctx, Cmd{Name: "openshell", Args: []string{"--version"}, Stdout: &v, Stderr: &v})
	if !strings.Contains(v.String(), strings.TrimPrefix(Version, "v")) {
		deb, ok := Debs[r.Arch]
		if !ok {
			return fmt.Errorf("openshell: no %s package for %s", Version, r.Arch)
		}
		progress("downloading OpenShell " + Version)
		path := filepath.Join("/var/cache/kevaso", deb.File)
		if err := download(ctx, DebURL(deb.File), path, deb.SHA256); err != nil {
			return err
		}
		progress("installing OpenShell " + Version)
		unlock := hostpkg.Lock()
		err := r.run(ctx, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get -o "+hostpkg.LockTimeout+" install -y -q "+path)
		unlock()
		if err != nil {
			return err
		}
	}
	_ = r.run(ctx, "systemctl", "--global", "disable", "openshell-gateway.service")
	for _, d := range []string{StateDir, StateDir + "/gw"} {
		if err := r.run(ctx, "install", "-d", "-m", "0711", d); err != nil { // gateway users only traverse
			return err
		}
	}
	progress("OpenShell " + Version + " ready (" + r.Driver + " driver, gateway per " + r.scope() + ")")
	return nil
}

var installMu sync.Mutex

// download fetches url to path and checks its SHA-256 before keeping it.
func download(ctx context.Context, url, path, sum string) error {
	if b, err := os.ReadFile(path); err == nil {
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) == sum {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
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
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: sha256 %s, want %s", url, got, sum)
	}
	return os.Rename(tmp, path)
}
