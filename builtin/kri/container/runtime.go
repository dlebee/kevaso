// Package container is the `docker` and `podman` runtimes (design §6, the container family): each
// silo is a container on the host kernel, persisting through volumes.
//
// Containers sit on the same silo bridge as the VMs, with an address from the same pool, so the host
// firewall, default-deny egress, allowFrom, exposure and the egress gate apply to them unchanged.
// Each silo has a small pause container that holds its network namespace: Kevaso wires a veth from
// the bridge into it (named like a VM's tap, so the anti-spoofing rules hold), and the silo's init
// containers and main container join it. The pause image is built on the host from kevasod itself:
// nothing is pulled for it.
//
// The broker reaches a container through a unix socket of its own, mounted at /run/kevaso: the
// socket a connection arrives on says which silo it is, as vsock does for VMs. kvo-guest (kevasod)
// and the host's CA bundle with the egress CA are mounted in read-only.
package container

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// Dir is where silos are kept (shared with the VM runtime's address allocation).
const Dir = cloudhypervisor.ContainersDir

// Images maps Kevaso's image names to registry references; anything else is used as is.
var Images = map[string]string{"ubuntu-24.04": "docker.io/library/ubuntu:24.04"}

// Runtime is one container engine as a KRI runtime.
type Runtime struct {
	Host   hostexec.Runner
	Engine string // docker | podman
	// Self is kevasod's own binary: the pause container's process, and kvo-guest in every silo.
	Self string
	// CABundle is the host's trusted CAs plus its egress CA, mounted into every silo.
	CABundle []byte
	Version  string

	mu sync.Mutex
}

type state struct {
	ID      kri.ID       `json:"id"`
	IP      string       `json:"ip"`
	Image   string       `json:"image"`
	Command []string     `json:"command,omitempty"`
	Volumes []kri.Volume `json:"volumes,omitempty"`
	CPU     int          `json:"cpu,omitempty"`
	Memory  int64        `json:"memory,omitempty"`
}

// Names are everything a silo owns.
type Names struct {
	Short, Dir, Main, Pause, Init, Veth, Peer string
}

// NamesFor returns a silo's names (its veth is named like a VM's tap).
func NamesFor(id kri.ID) Names {
	n := cloudhypervisor.NamesFor(id)
	return Names{Short: n.Short, Dir: Dir + "/" + n.Short, Main: "kv-" + n.Short, Pause: "kv-" + n.Short + "-pause",
		Init: "kv-" + n.Short + "-init", Veth: n.Tap, Peer: "kvp" + n.Short}
}

// VolumeName is a silo volume's name in the engine.
func VolumeName(id kri.ID, vol string) string { return "kv-" + NamesFor(id).Short + "-" + vol }

// ImageRef is the reference an image name pulls.
func ImageRef(image string) string {
	if r, ok := Images[image]; ok {
		return r
	}
	return image
}

// MainCommand is the main process: the silo's command, or for the ubuntu-24.04 image (whose own
// command exits at once) one that stays up, so the silo is a machine to exec into.
func MainCommand(image string, command []string) []string {
	if len(command) > 0 {
		return command
	}
	if image == "ubuntu-24.04" || image == "" {
		return []string{"sleep", "infinity"}
	}
	return nil
}

func (r *Runtime) engine() string {
	if r.Engine == "" {
		return "docker"
	}
	return r.Engine
}

// Info implements kri.Runtime.
func (r *Runtime) Info() kri.Info {
	return kri.Info{Name: r.engine(), Version: r.Version, Capabilities: kri.Capabilities{
		Isolation: "container", Network: "netns", UDP: true, InboundServices: true, Persistence: "volume", Injection: true, Exec: true,
	}}
}

func statePath(id kri.ID) string { return NamesFor(id).Dir + "/state.json" }

func (r *Runtime) load(id kri.ID) (state, bool) {
	b, err := r.Host.ReadFile(statePath(id))
	if err != nil {
		return state{}, false
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.ID != id {
		return state{}, false
	}
	return s, true
}

func (r *Runtime) save(s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return r.Host.WriteFile(statePath(s.ID), b, 0o600)
}

// eng runs the engine's CLI and returns stdout.
func (r *Runtime) eng(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	return r.cmd(ctx, stdin, r.engine(), args...)
}

func (r *Runtime) cmd(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	code, err := r.Host.Run(ctx, hostexec.Cmd{Name: name, Args: args, Stdin: stdin, Stdout: &out, Stderr: &errb})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	if err != nil {
		return out.Bytes(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// inspect returns a container's state ("" when it doesn't exist) and its process id.
func (r *Runtime) inspect(ctx context.Context, name string) (string, int, error) {
	out, err := r.eng(ctx, nil, "container", "inspect", "--format", "{{.State.Status}} {{.State.Pid}}", name)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such") {
			return "", 0, nil
		}
		return "", 0, err
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return "", 0, fmt.Errorf("inspect %s: %q", name, out)
	}
	pid, _ := strconv.Atoi(f[1])
	return f[0], pid, nil
}

// ── the pause image and container ────────────────────────────────────────────

// pauseImage builds (once per kevasod build) an image whose only file is kevasod, run as kevaso-pause.
func (r *Runtime) pauseImage(ctx context.Context) (string, error) {
	bin, err := os.ReadFile(r.Self)
	if err != nil {
		return "", fmt.Errorf("pause image: %w", err)
	}
	sum := sha256.Sum256(bin)
	tag := "localhost/kevaso-pause:" + hex.EncodeToString(sum[:6])
	if _, err := r.eng(ctx, nil, "image", "inspect", tag); err == nil {
		return tag, nil
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "kevaso-pause", Mode: 0o755, Size: int64(len(bin)), ModTime: time.Unix(0, 0)}); err != nil {
		return "", err
	}
	if _, err := tw.Write(bin); err != nil {
		return "", err
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if _, err := r.eng(ctx, &buf, "import", "--change", `ENTRYPOINT ["/kevaso-pause"]`, "-", tag); err != nil {
		return "", err
	}
	return tag, nil
}

// ensurePause has the silo's pause container running with its network wired to the bridge.
func (r *Runtime) ensurePause(ctx context.Context, s state) error {
	n := NamesFor(s.ID)
	st, _, err := r.inspect(ctx, n.Pause)
	if err != nil {
		return err
	}
	switch st {
	case "running":
	case "":
		img, err := r.pauseImage(ctx)
		if err != nil {
			return err
		}
		if _, err := r.eng(ctx, nil, "run", "-d", "--name", n.Pause, "--hostname", s.ID.Name, "--network", "none", "--read-only", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges", "--label", "kevaso.com/uid="+s.ID.UID, img); err != nil {
			return err
		}
	default:
		if _, err := r.eng(ctx, nil, "start", n.Pause); err != nil {
			return err
		}
	}
	st, pid, err := r.inspect(ctx, n.Pause)
	if err != nil || st != "running" || pid == 0 {
		return fmt.Errorf("pause container %s: %s (pid %d) %v", n.Pause, st, pid, err)
	}
	return r.wire(ctx, s, pid)
}

// wire puts a veth from the bridge into the pause container's network namespace, with the silo's
// address. It's done again whenever the namespace is new (a new pause container, a host reboot).
func (r *Runtime) wire(ctx context.Context, s state, pid int) error {
	n := NamesFor(s.ID)
	p := strconv.Itoa(pid)
	if out, err := r.cmd(ctx, nil, "nsenter", "-t", p, "-n", "ip", "-4", "-o", "addr", "show", "dev", "eth0"); err == nil && strings.Contains(string(out), " "+s.IP+"/") {
		return nil // already wired
	}
	bits := strconv.Itoa(cloudhypervisor.Network.Bits())
	steps := [][]string{
		{"ip", "link", "add", n.Veth, "type", "veth", "peer", "name", n.Peer},
		{"ip", "link", "set", n.Peer, "netns", p},
		{"nsenter", "-t", p, "-n", "ip", "link", "set", n.Peer, "name", "eth0"},
		{"nsenter", "-t", p, "-n", "ip", "addr", "add", s.IP + "/" + bits, "dev", "eth0"},
		{"nsenter", "-t", p, "-n", "ip", "link", "set", "lo", "up"},
		{"nsenter", "-t", p, "-n", "ip", "link", "set", "eth0", "up"},
		{"nsenter", "-t", p, "-n", "ip", "route", "add", "default", "via", cloudhypervisor.Gateway.String()},
		{"ip", "link", "set", n.Veth, "master", cloudhypervisor.Bridge, "up"},
	}
	_, _ = r.cmd(ctx, nil, "ip", "link", "del", n.Veth) // an old one, from a namespace that's gone
	for _, st := range steps {
		if _, err := r.cmd(ctx, nil, st[0], st[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// ── lifecycle ────────────────────────────────────────────────────────────────

// Create implements kri.Runtime: an address, the image, the volumes, the pause container wired to
// the bridge. The main container comes with Start.
func (r *Runtime) Create(ctx context.Context, spec kri.Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(spec.ID)
	if !ok {
		cloudhypervisor.IPMu.Lock()
		ip, err := cloudhypervisor.AllocateIP(cloudhypervisor.UsedIPs(chHost{r.Host}))
		if err == nil {
			s = state{ID: spec.ID, IP: ip.String(), Image: spec.Image, Command: spec.Command, Volumes: spec.Volumes, CPU: spec.CPU, Memory: spec.Memory}
			err = r.save(s)
		}
		cloudhypervisor.IPMu.Unlock()
		if err != nil {
			return err
		}
	}
	n := NamesFor(spec.ID)
	files := map[string][]byte{
		n.Dir + "/resolv.conf":   []byte(fmt.Sprintf("nameserver %s\nsearch %s.kevaso kevaso\n", cloudhypervisor.Gateway, spec.ID.Namespace)),
		n.Dir + "/ca-bundle.crt": r.CABundle,
	}
	for p, b := range files {
		if err := r.Host.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	if _, err := r.cmd(ctx, nil, "install", "-d", "-m", "0700", n.Dir+"/broker"); err != nil {
		return err
	}
	if _, err := r.eng(ctx, nil, "pull", "--quiet", ImageRef(s.Image)); err != nil {
		return err
	}
	for _, v := range s.Volumes {
		name := VolumeName(s.ID, v.Name)
		if _, err := r.eng(ctx, nil, "volume", "inspect", name); err == nil {
			continue
		}
		if _, err := r.eng(ctx, nil, "volume", "create", "--label", "kevaso.com/uid="+s.ID.UID, name); err != nil {
			return err
		}
	}
	return r.ensurePause(ctx, s)
}

// runArgs are a silo container's settings: the pause container's network, the volumes, the
// broker, kvo-guest and the CA bundle, limits, no new privileges.
func (r *Runtime) runArgs(s state, name string) []string {
	n := NamesFor(s.ID)
	args := []string{"--name", name, "--network", "container:" + n.Pause,
		"--security-opt", "no-new-privileges", "--pids-limit", "4096",
		"--label", "kevaso.com/namespace=" + s.ID.Namespace, "--label", "kevaso.com/name=" + s.ID.Name, "--label", "kevaso.com/uid=" + s.ID.UID,
		"-v", n.Dir + "/resolv.conf:/etc/resolv.conf:ro",
		"-v", n.Dir + "/broker:/run/kevaso",
		"-e", "KVO_GUEST_BROKER=unix:/run/kevaso/broker.sock"}
	if r.engine() == "podman" { // docker shares the hostname with the network; podman needs asking
		args = append(args, "--uts", "container:"+n.Pause)
	}
	if r.Self != "" {
		args = append(args, "-v", r.Self+":/usr/local/bin/kvo-guest:ro")
	}
	if len(r.CABundle) > 0 {
		const ca = "/etc/ssl/certs/kevaso-ca-bundle.crt"
		args = append(args, "-v", n.Dir+"/ca-bundle.crt:"+ca+":ro",
			"-e", "SSL_CERT_FILE="+ca, "-e", "REQUESTS_CA_BUNDLE="+ca, "-e", "CURL_CA_BUNDLE="+ca, "-e", "NODE_EXTRA_CA_CERTS="+ca)
	}
	for _, v := range s.Volumes {
		args = append(args, "-v", VolumeName(s.ID, v.Name)+":"+v.MountPath)
	}
	if s.CPU > 0 {
		args = append(args, "--cpus", strconv.Itoa(s.CPU))
	}
	if s.Memory > 0 {
		args = append(args, "--memory", strconv.FormatInt(s.Memory, 10))
	}
	return args
}

// Start implements kri.Runtime: the pause container first (rewired after a reboot), then the main
// container, made the first time.
func (r *Runtime) Start(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if err := r.ensurePause(ctx, s); err != nil {
		return err
	}
	n := NamesFor(id)
	st, _, err := r.inspect(ctx, n.Main)
	if err != nil {
		return err
	}
	switch st {
	case "running":
		return nil
	case "":
		args := append([]string{"run", "-d"}, r.runArgs(s, n.Main)...)
		args = append(args, ImageRef(s.Image))
		args = append(args, MainCommand(s.Image, s.Command)...)
		_, err = r.eng(ctx, nil, args...)
	default:
		_, err = r.eng(ctx, nil, "start", n.Main)
	}
	return err
}

// RunInit implements kri.InitContainers: one step in a container of its own from the silo's
// image, on its network and volumes, before the main container starts.
func (r *Runtime) RunInit(ctx context.Context, id kri.ID, step kri.InitStep, out io.Writer) (int, error) {
	s, ok := r.load(id)
	if !ok {
		return -1, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if err := r.ensurePause(ctx, s); err != nil {
		return -1, err
	}
	n := NamesFor(id)
	_, _ = r.eng(ctx, nil, "rm", "-f", n.Init) // a leftover from an interrupted run
	shell := step.Shell
	if shell == "" {
		shell = "sh"
	}
	args := append([]string{"run", "--rm"}, r.runArgs(s, n.Init)...)
	args = append(args, "--entrypoint", shell, ImageRef(s.Image), "-c", step.Run)
	return r.Host.Run(ctx, hostexec.Cmd{Name: r.engine(), Args: args, Stdout: out, Stderr: out})
}

// Stop implements kri.Runtime (the pause container keeps the address).
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	if _, ok := r.load(id); !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	st, _, err := r.inspect(ctx, NamesFor(id).Main)
	if err != nil || st == "" || st != "running" {
		return err
	}
	_, err = r.eng(ctx, nil, "stop", "-t", "20", NamesFor(id).Main)
	return err
}

// Delete implements kri.Runtime: the containers, volumes, veth and state.
func (r *Runtime) Delete(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return nil
	}
	n := NamesFor(id)
	for _, c := range []string{n.Main, n.Init, n.Pause} {
		if _, err := r.eng(ctx, nil, "rm", "-f", c); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such") {
			return err
		}
	}
	for _, v := range s.Volumes {
		_, _ = r.eng(ctx, nil, "volume", "rm", "-f", VolumeName(id, v.Name))
	}
	_, _ = r.cmd(ctx, nil, "ip", "link", "del", n.Veth)
	return r.Host.RemoveAll(n.Dir)
}

// Status implements kri.Runtime.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	s, ok := r.load(id)
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	st, _, err := r.inspect(ctx, NamesFor(id).Main)
	if err != nil {
		return kri.Status{}, err
	}
	switch st {
	case "":
		return kri.Status{State: kri.Created}, nil
	case "running", "restarting":
		if ps, _, _ := r.inspect(ctx, NamesFor(id).Pause); ps != "running" {
			return kri.Status{State: kri.Stopped}, nil // its network is gone: Start rewires it
		}
		return kri.Status{State: kri.Running, Address: s.IP}, nil
	case "dead":
		return kri.Status{State: kri.Failed, Message: "the container is dead"}, nil
	}
	return kri.Status{State: kri.Stopped}, nil // created, exited, paused
}

// List implements kri.Runtime.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	paths, _ := r.Host.Glob(Dir + "/*/state.json")
	var ids []kri.ID
	for _, p := range paths {
		b, err := r.Host.ReadFile(p)
		if err != nil {
			continue
		}
		var s state
		if json.Unmarshal(b, &s) == nil {
			ids = append(ids, s.ID)
		}
	}
	return ids, nil
}

// Exec implements kri.Runtime: `docker exec -i`, stdin, stdout, stderr and the exit code passed through.
func (r *Runtime) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	if _, ok := r.load(id); !ok {
		return -1, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if st, _, err := r.inspect(ctx, NamesFor(id).Main); err != nil || st != "running" {
		return -1, fmt.Errorf("%s is not running (%s) %v", id, st, err)
	}
	args := []string{"exec"}
	if req.Stdin != nil {
		args = append(args, "-i")
	}
	args = append(append(args, NamesFor(id).Main), req.Command...)
	return r.Host.Run(ctx, hostexec.Cmd{Name: r.engine(), Args: args, Stdin: req.Stdin, Stdout: orDiscard(req.Stdout), Stderr: orDiscard(req.Stderr)})
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// BrokerListen implements kri.Broker: a unix socket in the silo's own directory, which only its
// containers mount (at /run/kevaso/broker.sock).
func (r *Runtime) BrokerListen(id kri.ID, _ uint32) (net.Listener, error) {
	if _, ok := r.load(id); !ok {
		return nil, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	path := NamesFor(id).Dir + "/broker/broker.sock"
	_ = r.Host.RemoveAll(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil { // any user in the silo; no one outside sees the dir
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// chHost adapts the runner to the VM runtime's host interface (for the shared address pool).
type chHost struct{ h hostexec.Runner }

func (c chHost) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	var out bytes.Buffer
	code, err := c.h.Run(ctx, hostexec.Cmd{Name: name, Args: args, Stdout: &out, Stderr: &out})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	return out.Bytes(), err
}
func (c chHost) WriteFile(p string, d []byte, m os.FileMode) error { return c.h.WriteFile(p, d, m) }
func (c chHost) ReadFile(p string) ([]byte, error)                 { return c.h.ReadFile(p) }
func (c chHost) RemoveAll(p string) error                          { return c.h.RemoveAll(p) }
func (c chHost) Glob(p string) ([]string, error)                   { return c.h.Glob(p) }

var (
	_ kri.Runtime        = (*Runtime)(nil)
	_ kri.InitContainers = (*Runtime)(nil)
	_ kri.Broker         = (*Runtime)(nil)
)
