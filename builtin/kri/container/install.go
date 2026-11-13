package container

import (
	"context"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/hostpkg"
)

// Packages are what each engine needs from the distribution (nsenter comes with util-linux).
var Packages = map[string][]string{
	"docker": {"docker.io", "nftables", "iproute2"},
	"podman": {"podman", "catatonit", "nftables", "iproute2"}, // catatonit: podman's run --init
}

// DockerDaemonJSON keeps Docker out of the host's firewall and networks: container silos use the
// silo bridge, through their pause container. live-restore keeps containers running while
// dockerd itself restarts (a package upgrade, a change to this file).
const DockerDaemonJSON = `{
  "iptables": false,
  "ip6tables": false,
  "bridge": "none",
  "live-restore": true
}
`

// Install readies the host: the engine, and the silo bridge with its baseline firewall (shared with
// the VM runtime).
func (r *Runtime) Install(ctx context.Context, progress func(string)) error {
	if progress == nil {
		progress = func(string) {}
	}
	progress("packages")
	if err := r.installPackages(ctx); err != nil {
		return err
	}
	if r.engine() == "docker" {
		// Kevaso owns the host's firewall and networks its containers itself (the silo bridge), so
		// Docker mustn't: left alone it sets the FORWARD policy to DROP, which no rule of ours can
		// undo, and every silo's forwarded traffic (VMs too) would stop.
		// Install runs at every kevasod start (an upgrade, a restart): dockerd restarts only when
		// its configuration changed, never just because the agent did, so silos keep running.
		if cur, err := r.Host.ReadFile("/etc/docker/daemon.json"); err != nil || string(cur) != DockerDaemonJSON {
			if err := r.Host.WriteFile("/etc/docker/daemon.json", []byte(DockerDaemonJSON), 0o644); err != nil {
				return err
			}
			if _, err := r.cmd(ctx, nil, "systemctl", "enable", "docker"); err != nil {
				return err
			}
			if _, err := r.cmd(ctx, nil, "systemctl", "restart", "docker"); err != nil {
				return err
			}
		}
		if _, err := r.cmd(ctx, nil, "systemctl", "enable", "--now", "docker"); err != nil { // running, whatever happened since
			return err
		}
		_, _ = r.cmd(ctx, nil, "sh", "-c", "iptables -P FORWARD ACCEPT 2>/dev/null; ip link del docker0 2>/dev/null; true")
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

// installPackages installs the engine's packages, one runtime at a time on the host (hostpkg).
func (r *Runtime) installPackages(ctx context.Context) error {
	defer hostpkg.Lock()()
	args := append([]string{"-c", "DEBIAN_FRONTEND=noninteractive apt-get -o " + hostpkg.LockTimeout + " install -y -q \"$@\"", "sh"}, Packages[r.engine()]...)
	if _, err := r.cmd(ctx, nil, "sh", args...); err != nil {
		if _, uerr := r.cmd(ctx, nil, "sh", "-c", hostpkg.Update); uerr != nil {
			return err
		}
		if _, err := r.cmd(ctx, nil, "sh", args...); err != nil {
			return err
		}
	}
	return nil
}
