package container

import (
	"context"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
)

// Packages are what each engine needs from the distribution (nsenter comes with util-linux).
var Packages = map[string][]string{
	"docker": {"docker.io", "nftables", "iproute2"},
	"podman": {"podman", "nftables", "iproute2"},
}

// Install readies the host: the engine, and the silo bridge with its baseline firewall (shared with
// the VM runtime).
func (r *Runtime) Install(ctx context.Context, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	progress("packages")
	args := append([]string{"-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y -q \"$@\"", "sh"}, Packages[r.engine()]...)
	if _, err := r.cmd(ctx, nil, "sh", args...); err != nil {
		if _, uerr := r.cmd(ctx, nil, "sh", "-c", "DEBIAN_FRONTEND=noninteractive apt-get update -q"); uerr != nil {
			return err
		}
		if _, err := r.cmd(ctx, nil, "sh", args...); err != nil {
			return err
		}
	}
	if r.engine() == "docker" {
		if _, err := r.cmd(ctx, nil, "systemctl", "enable", "--now", "docker"); err != nil {
			return err
		}
	}
	progress("silo bridge")
	if err := cloudhypervisor.SetupNetwork(ctx, chHost{r.Host}); err != nil {
		return err
	}
	if _, err := r.cmd(ctx, nil, "install", "-d", "-m", "0700", Dir); err != nil {
		return err
	}
	out, _ := r.eng(ctx, nil, "--version")
	if len(out) > 0 {
		r.Version = string(trim(out))
	}
	progress(r.engine() + " ready")
	return nil
}

func trim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
