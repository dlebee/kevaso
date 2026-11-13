package container

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/container/ocienv"
	"kevaso.com/core/builtin/kri/hostpkg"
)

// Packages are what each engine needs from the distribution (nsenter comes with util-linux).
var Packages = map[string][]string{
	"docker": {"docker.io", "nftables", "iproute2"},
	"podman": {"podman", "catatonit", "nftables", "iproute2"}, // catatonit: podman's run --init
}

// DockerDaemonConfig is /etc/docker/daemon.json as Kevaso needs it, from what's there: Docker kept
// out of the host's firewall and networks (container silos use the silo bridge, through their
// pause container), live-restore (containers keep running while dockerd itself restarts: a
// package upgrade, a change to this file), and Kevaso's OCI runtime registered as kevaso-oci when
// register (ocienv: env secrets without the engine keeping them), removed when not. Every other
// key, and every other runtime, is kept. changed is false when cur already says all that (however
// it's laid out): dockerd isn't restarted for nothing. Pure.
func DockerDaemonConfig(cur []byte, register bool) (next []byte, changed bool) {
	m := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(cur))
	dec.UseNumber()
	valid := dec.Decode(&m) == nil && m != nil
	if !valid {
		m = map[string]any{}
	}
	before, _ := json.MarshalIndent(m, "", "  ")
	m["iptables"], m["ip6tables"], m["bridge"], m["live-restore"] = false, false, "none", true
	rts, _ := m["runtimes"].(map[string]any)
	if rts == nil {
		rts = map[string]any{}
	}
	if register {
		rts[ocienv.RuntimeName] = map[string]any{"path": ocienv.ShimPath}
	} else {
		delete(rts, ocienv.RuntimeName)
	}
	if len(rts) > 0 {
		m["runtimes"] = rts
	} else {
		delete(m, "runtimes")
	}
	next, _ = json.MarshalIndent(m, "", "  ")
	changed = !valid || !bytes.Equal(before, next)
	return append(next, '\n'), changed
}

const daemonJSON = "/etc/docker/daemon.json"

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
		if err := r.installDocker(ctx); err != nil {
			return err
		}
	} else {
		r.setEnvPath(false, "podman writes the container's OCI config to its storage on the host's disk (the bundle is under its graph root), so a runtime in front of crun would put the variables on disk too")
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

// installDocker configures dockerd (DockerDaemonConfig), with Kevaso's OCI runtime in front of
// runc when it can be: then env secrets reach containers through it (EnvOutsideEngine), else
// through --env-file as before, and the runtime says why (setEnvPath).
func (r *Runtime) installDocker(ctx context.Context) error {
	cur, _ := r.Host.ReadFile(daemonJSON)
	real, why := r.realDockerRuntime(ctx, cur)
	if real != "" {
		if err := r.registerShim(ctx, real); err != nil {
			real, why = "", "Kevaso's OCI runtime couldn't be set up: "+err.Error()
		}
	}
	// Kevaso owns the host's firewall and networks its containers itself (the silo bridge), so
	// Docker mustn't: left alone it sets the FORWARD policy to DROP, which no rule of ours can
	// undo, and every silo's forwarded traffic (VMs too) would stop.
	// Install runs at every kevasod start: dockerd restarts only when its configuration changed,
	// never just because the agent did, so silos keep running.
	if next, changed := DockerDaemonConfig(cur, real != ""); changed {
		if err := r.Host.WriteFile(daemonJSON, next, 0o644); err != nil {
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
	if real != "" {
		why = r.dockerTakesShim(ctx)
	}
	r.setEnvPath(why == "", why)
	return nil
}

// realDockerRuntime is the runtime dockerd runs containers with, which kevaso-oci hands over to:
// runc, found where dockerd finds it. "" and why when it isn't runc (gVisor's runsc, Kata: their
// bundles and processes aren't runc's) or isn't there. Decided here, at install, never guessed
// when a container starts.
func (r *Runtime) realDockerRuntime(ctx context.Context, cur []byte) (string, string) {
	var c struct {
		DefaultRuntime string `json:"default-runtime"`
	}
	_ = json.Unmarshal(cur, &c)
	if c.DefaultRuntime != "" && c.DefaultRuntime != "runc" {
		return "", "Docker's default runtime here is " + c.DefaultRuntime + ", not runc, which Kevaso's OCI runtime hands over to"
	}
	if r.Self == "" || !path.IsAbs(r.Self) {
		return "", "kevasod's own path isn't known"
	}
	out, err := r.cmd(ctx, nil, "sh", "-c", "command -v runc")
	p := strings.TrimSpace(string(out))
	if err != nil || !path.IsAbs(p) {
		return "", "runc isn't on the host's PATH"
	}
	return p, ""
}

// registerShim writes kevaso-oci's configuration (the real runtime) and links it to kevasod.
func (r *Runtime) registerShim(ctx context.Context, real string) error {
	if _, err := r.cmd(ctx, nil, "install", "-d", "-m", "0755", path.Dir(ocienv.ConfigPath), path.Dir(ocienv.ShimPath)); err != nil {
		return err
	}
	b, _ := json.Marshal(ocienv.Config{Runtime: real})
	if err := r.Host.WriteFile(ocienv.ConfigPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	_, err := r.cmd(ctx, nil, "ln", "-sfn", r.Self, ocienv.ShimPath)
	return err
}

// dockerTakesShim asks the running dockerd whether containers can start through kevaso-oci: it's
// registered, the engine isn't rootless, runc is its default, and its API has annotations (1.43,
// Docker 24), which carry the silo's short id. "" when it can, else why not.
func (r *Runtime) dockerTakesShim(ctx context.Context) string {
	out, err := r.eng(ctx, nil, "info", "--format", "{{.DefaultRuntime}}\n{{json .Runtimes}}\n{{json .SecurityOptions}}")
	if err != nil {
		return "docker info: " + err.Error()
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 3)
	if len(lines) < 3 {
		return "docker info said nothing of its runtimes"
	}
	var rts map[string]any
	var sec []string
	_ = json.Unmarshal([]byte(lines[1]), &rts)
	_ = json.Unmarshal([]byte(lines[2]), &sec)
	switch {
	case slices.ContainsFunc(sec, func(s string) bool { return strings.Contains(s, "name=rootless") }):
		return "Docker runs rootless here"
	case lines[0] != "runc":
		return "Docker's default runtime here is " + lines[0] + ", not runc"
	case rts[ocienv.RuntimeName] == nil:
		return "Docker didn't take Kevaso's OCI runtime (" + ocienv.RuntimeName + " isn't among its runtimes)"
	}
	v, err := r.eng(ctx, nil, "version", "--format", "{{.Server.APIVersion}}")
	if err != nil || !apiAtLeast(strings.TrimSpace(string(v)), 1, 43) {
		return "Docker's API (" + strings.TrimSpace(string(v)) + ") is older than 1.43 (Docker 24): it can't set a container's annotations"
	}
	return ""
}

// apiAtLeast compares a MAJOR.MINOR version.
func apiAtLeast(v string, major, minor int) bool {
	a, b, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	ma, err1 := strconv.Atoi(a)
	mi, err2 := strconv.Atoi(b)
	return err1 == nil && err2 == nil && (ma > major || ma == major && mi >= minor)
}
