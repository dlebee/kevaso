package openshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// Cmd, Runner and Local are the shared host command runner.
type (
	Cmd    = hostexec.Cmd
	Runner = hostexec.Runner
	Local  = hostexec.Local
)

// Runtime is one OpenShell driver as a KRI runtime.
type Runtime struct {
	Host    Runner
	Name    string // openshell | openshell-container
	Driver  string // vm | docker
	Scope   string // host | namespace (default) | silo
	ExtraCA string // a PEM file the gateway's proxy trusts upstream (on top of the system's)
	Arch    string // x86_64 | aarch64
	// Wait is how long to wait for a new gateway and for a sandbox to be Ready (default 3 minutes).
	Wait time.Duration
	// Sleep pauses between polls (tests: no-op).
	Sleep func(time.Duration)

	mu sync.Mutex
}

// state is what the runtime remembers about a silo.
type state struct {
	ID         kri.ID           `json:"id"`
	Gateway    Gateway          `json:"gateway"`
	Image      string           `json:"image,omitempty"`
	CPU        int              `json:"cpu"`
	Memory     int64            `json:"memory"`
	Created    bool             `json:"created"`    // the sandbox exists in OpenShell
	PolicyHash string           `json:"policyHash"` // last applied
	Providers  map[string]int64 `json:"providers"`  // provider name → credential version applied
}

func (r *Runtime) wait() time.Duration {
	if r.Wait > 0 {
		return r.Wait
	}
	return 3 * time.Minute
}

func (r *Runtime) sleep(d time.Duration) {
	if r.Sleep != nil {
		r.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (r *Runtime) scope() string {
	if r.Scope == "" {
		return ScopeNamespace
	}
	return r.Scope
}

func statePath(id kri.ID) string { return StateDir + "/silos/" + Short(id) + ".json" }

func (r *Runtime) load(id kri.ID) (state, bool) {
	b, err := r.Host.ReadFile(statePath(id))
	if err != nil {
		return state{}, false
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.ID != id {
		return state{}, false
	}
	if s.Providers == nil {
		s.Providers = map[string]int64{}
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

func (r *Runtime) all() []state {
	paths, _ := r.Host.Glob(StateDir + "/silos/*.json")
	var out []state
	for _, p := range paths {
		b, err := r.Host.ReadFile(p)
		if err != nil {
			continue
		}
		var s state
		if json.Unmarshal(b, &s) == nil {
			out = append(out, s)
		}
	}
	return out
}

// cli runs `openshell ARGS` against gateway g and returns stdout (stderr in the error).
func (r *Runtime) cli(ctx context.Context, g Gateway, stdin io.Reader, env []string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	code, err := r.Host.Run(ctx, Cmd{Name: "openshell", Args: args, Env: append(g.Env(), env...), Stdin: stdin, Stdout: &out, Stderr: &errb})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	if err != nil {
		return out.Bytes(), fmt.Errorf("openshell %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (r *Runtime) run(ctx context.Context, name string, args ...string) error {
	var out bytes.Buffer
	code, err := r.Host.Run(ctx, Cmd{Name: name, Args: args, Stdout: &out, Stderr: &out})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Info implements kri.Runtime.
func (r *Runtime) Info() kri.Info {
	iso := "vm"
	if r.Driver == DriverDocker {
		iso = "container"
	}
	return kri.Info{Name: r.Name, Version: Version, Capabilities: kri.Capabilities{
		Isolation: iso, Network: "proxy", UDP: false, InboundServices: false, Persistence: "workspace", Injection: true, Exec: true,
	}}
}

// ── gateways ─────────────────────────────────────────────────────────────────

const gatewaysFile = StateDir + "/gateways.json"

// gateway finds or sets up the gateway for key: its user, directories, config and locked-down
// unit, started and registered with the CLI.
func (r *Runtime) gateway(ctx context.Context, key string) (Gateway, error) {
	gws := map[string]Gateway{}
	if b, err := r.Host.ReadFile(gatewaysFile); err == nil {
		_ = json.Unmarshal(b, &gws)
	}
	g, ok := gws[key]
	if !ok {
		used := map[int]bool{}
		for _, o := range gws {
			used[o.Port] = true
		}
		port := BasePort
		for used[port] {
			port++
		}
		g = Gateway{Key: key, Port: port, Driver: r.Driver}
		gws[key] = g
		b, _ := json.MarshalIndent(gws, "", "  ")
		if err := r.Host.WriteFile(gatewaysFile, b, 0o600); err != nil {
			return g, err
		}
	}
	if _, err := r.cli(ctx, g, nil, nil, "sandbox", "list", "-o", "json"); err == nil {
		return g, nil // up and registered
	}
	if err := r.setupGateway(ctx, g); err != nil {
		return g, fmt.Errorf("gateway %s: %w", g.Key, err)
	}
	return g, nil
}

func (r *Runtime) setupGateway(ctx context.Context, g Gateway) error {
	user, dir := g.User(), g.Dir()
	group := "kvm"
	if g.Driver == DriverDocker {
		group = "docker"
	}
	if err := r.run(ctx, "id", "-u", user); err != nil {
		if err := r.run(ctx, "useradd", "--system", "--home-dir", dir, "--shell", "/usr/sbin/nologin", "--groups", group, user); err != nil {
			return err
		}
	}
	for _, d := range []string{dir, dir + "/.config", dir + "/.config/openshell", dir + "/.local", dir + "/.local/state", dir + "/.local/share"} {
		if err := r.run(ctx, "install", "-d", "-m", "0700", "-o", user, "-g", user, d); err != nil {
			return err
		}
	}
	files := map[string]string{
		dir + "/.config/openshell/gateway.env":  g.EnvFile(),
		dir + "/.config/openshell/gateway.toml": g.TOML(r.ExtraCA),
	}
	for p, c := range files {
		if err := r.Host.WriteFile(p, []byte(c), 0o600); err != nil {
			return err
		}
		if err := r.run(ctx, "chown", user+":"+user, p); err != nil {
			return err
		}
	}
	if err := r.Host.WriteFile("/etc/systemd/system/"+g.Unit(), []byte(g.UnitFile()), 0o644); err != nil {
		return err
	}
	if err := r.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := r.run(ctx, "systemctl", "enable", "--now", g.Unit()); err != nil {
		return err
	}
	// The gateway takes ~20 s to listen (E037); register the CLI once it answers.
	deadline := time.Now().Add(r.wait())
	var last error
	for {
		_, err := r.cli(ctx, g, nil, nil, "gateway", "add", g.Endpoint(), "--local", "--name", g.Name())
		if err != nil && strings.Contains(err.Error(), "already") { // registered by an earlier run
			err = nil
		}
		if err == nil {
			if _, err = r.cli(ctx, g, nil, nil, "sandbox", "list", "-o", "json"); err == nil {
				return nil
			}
		}
		last = err
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("never answered: %w", last)
		}
		r.sleep(3 * time.Second)
	}
}

// ── sandboxes ────────────────────────────────────────────────────────────────

// Create implements kri.Runtime: it records the silo and readies its gateway; OpenShell makes the
// sandbox on Start (its create also starts it).
func (r *Runtime) Create(ctx context.Context, spec kri.Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.load(spec.ID); ok {
		return nil
	}
	g, err := r.gateway(ctx, GatewayKey(r.Driver, r.scope(), spec.ID))
	if err != nil {
		return err
	}
	if err := r.run(ctx, "install", "-d", "-m", "0700", StateDir+"/silos", StateDir+"/policies"); err != nil {
		return err
	}
	s := state{ID: spec.ID, Gateway: g, Image: spec.Image, CPU: spec.CPU, Memory: spec.Memory, Providers: map[string]int64{}}
	if err := r.Host.WriteFile(policyPath(spec.ID), []byte(basePolicy), 0o600); err != nil {
		return err
	}
	return r.save(s)
}

func policyPath(id kri.ID) string { return StateDir + "/policies/" + Short(id) + ".yaml" }

type sandboxJSON struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Phase  string            `json:"phase"`
	Labels map[string]string `json:"labels"`
}

func (r *Runtime) get(ctx context.Context, s state) (sandboxJSON, bool, error) {
	out, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "get", SandboxName(s.ID), "-o", "json")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			return sandboxJSON{}, false, nil
		}
		return sandboxJSON{}, false, err
	}
	var sb sandboxJSON
	if err := json.Unmarshal(out, &sb); err != nil {
		return sandboxJSON{}, false, fmt.Errorf("sandbox get: %w", err)
	}
	return sb, true, nil
}

// Start implements kri.Runtime: the first time it creates the sandbox (with its policy and
// providers), afterwards it starts the stopped one.
func (r *Runtime) Start(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	if _, err := r.gateway(ctx, s.Gateway.Key); err != nil { // e.g. after a host reboot
		return err
	}
	_, exists, err := r.get(ctx, s)
	if err != nil {
		return err
	}
	if exists {
		_, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "start", SandboxName(id))
		return err
	}
	args := []string{"sandbox", "create", "--name", SandboxName(id), "--detach", "--no-tty", "--no-auto-providers",
		"--label", "kevaso.com/namespace=" + id.Namespace, "--label", "kevaso.com/name=" + id.Name, "--label", "kevaso.com/uid=" + id.UID,
		"--policy", policyPath(id), "-o", "json"}
	if s.CPU > 0 {
		args = append(args, "--cpu", strconv.Itoa(s.CPU))
	}
	if s.Memory > 0 {
		args = append(args, "--memory", Memory(s.Memory))
	}
	if from := imageRef(s.Image); from != "" {
		args = append(args, "--from", from)
	}
	names := make([]string, 0, len(s.Providers))
	for p := range s.Providers {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		args = append(args, "--provider", p)
	}
	if _, err := r.cli(ctx, s.Gateway, nil, nil, args...); err != nil {
		return err
	}
	s.Created = true
	return r.save(s)
}

// imageRef: Kevaso's ubuntu-24.04 is OpenShell's default image; anything else is passed as is (an
// image reference or a rootfs tar).
func imageRef(image string) string {
	if image == "" || image == "ubuntu-24.04" {
		return ""
	}
	return image
}

// Stop implements kri.Runtime.
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	s, ok := r.load(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	sb, exists, err := r.get(ctx, s)
	if err != nil || !exists || Phase(sb.Phase) == kri.Stopped {
		return err
	}
	_, err = r.cli(ctx, s.Gateway, nil, nil, "sandbox", "stop", SandboxName(id))
	return err
}

// Delete implements kri.Runtime: the sandbox, its providers and profiles, its state; a gateway of
// its own (scope silo) too.
func (r *Runtime) Delete(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return nil
	}
	if _, exists, err := r.get(ctx, s); err == nil && exists {
		if _, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "delete", SandboxName(id)); err != nil {
			return err
		}
	}
	for p := range s.Providers {
		_, _ = r.cli(ctx, s.Gateway, nil, nil, "provider", "delete", p)
		_, _ = r.cli(ctx, s.Gateway, nil, nil, "profile", "delete", p)
	}
	if r.scope() == ScopeSilo {
		_ = r.run(ctx, "systemctl", "disable", "--now", s.Gateway.Unit())
		_ = r.Host.RemoveAll("/etc/systemd/system/" + s.Gateway.Unit())
		_ = r.run(ctx, "userdel", s.Gateway.User())
		_ = r.Host.RemoveAll(s.Gateway.Dir())
	}
	_ = r.Host.RemoveAll(policyPath(id))
	return r.Host.RemoveAll(statePath(id))
}

// Reset implements kri.Resetter: the sandbox goes (its gateway and providers stay) and is made
// again from spec's image on Start, with the policy applied afresh.
func (r *Runtime) Reset(ctx context.Context, spec kri.Spec) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(spec.ID)
	if !ok {
		return fmt.Errorf("%s: %w", spec.ID, kri.ErrNotFound)
	}
	if _, exists, err := r.get(ctx, s); err != nil {
		return err
	} else if exists {
		if _, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "delete", SandboxName(spec.ID)); err != nil {
			return err
		}
	}
	s.Image, s.CPU, s.Memory, s.Created, s.PolicyHash = spec.Image, spec.CPU, spec.Memory, false, ""
	return r.save(s)
}

// Status implements kri.Runtime.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	s, ok := r.load(id)
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	if !s.Created {
		return kri.Status{State: kri.Created}, nil
	}
	sb, exists, err := r.get(ctx, s)
	if err != nil {
		return kri.Status{}, err
	}
	if !exists {
		return kri.Status{State: kri.Failed, Message: "the sandbox is gone from OpenShell"}, nil
	}
	st := Phase(sb.Phase)
	msg := ""
	if st == kri.Failed {
		msg = "OpenShell sandbox phase " + sb.Phase
	}
	return kri.Status{State: st, Message: msg}, nil
}

// List implements kri.Runtime.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	var ids []kri.ID
	for _, s := range r.all() {
		ids = append(ids, s.ID)
	}
	return ids, nil
}

// Exec implements kri.Runtime: `openshell sandbox exec`, as the sandbox's user, with stdin, stdout,
// stderr and the exit code passed through. It waits for the sandbox to be Ready first. OpenShell
// takes at most 4 MiB of piped stdin (larger files: compress them, or upload).
func (r *Runtime) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	s, ok := r.load(id)
	if !ok {
		return -1, fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	deadline := time.Now().Add(r.wait())
	for {
		sb, exists, err := r.get(ctx, s)
		if err != nil {
			return -1, err
		}
		if exists && strings.EqualFold(sb.Phase, "ready") {
			break
		}
		if !exists || Phase(sb.Phase) == kri.Stopped || Phase(sb.Phase) == kri.Failed {
			return -1, fmt.Errorf("%s is not running", id)
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return -1, fmt.Errorf("%s: not Ready after %s (phase %s)", id, r.wait(), sb.Phase)
		}
		r.sleep(2 * time.Second)
	}
	// The command carries a marker in its environment (through env, which every image with a
	// shell has), so that when the client goes away whatever it started is killed inside the
	// sandbox: killing the CLI isn't known to stop it. With a terminal the CLI runs on one of the
	// agent's own and picks the sandbox's terminal itself (no --no-tty).
	marker := hostexec.NewMarker()
	args := []string{"sandbox", "exec", "-n", SandboxName(id)}
	if req.TTY == nil {
		args = append(args, "--no-tty")
	}
	args = append(append(args, "--", "env", kri.ExecMarkerEnv+"="+marker), req.Command...)
	code, err := r.Host.Run(ctx, Cmd{Name: "openshell", Args: args, Env: s.Gateway.Env(), Stdin: req.Stdin, Stdout: orDiscard(req.Stdout), Stderr: orDiscard(req.Stderr), TTY: req.TTY})
	if ctx.Err() != nil {
		kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		sweep := []string{"sandbox", "exec", "-n", SandboxName(id), "--no-tty", "--", "sh", "-c", hostexec.SweepScript, "sh", marker}
		_, _ = r.Host.Run(kctx, Cmd{Name: "openshell", Args: sweep, Env: s.Gateway.Env(), Stdout: io.Discard, Stderr: io.Discard})
		return -1, ctx.Err()
	}
	return code, err
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

// ── policy and credentials ───────────────────────────────────────────────────

// SetPolicy implements kri.Policied: the silo's grants as OpenShell's policy (replaced whole), and
// one provider per injected credential, created, rotated, attached and removed as needed. Values go
// to the CLI through its environment, never its arguments.
func (r *Runtime) SetPolicy(ctx context.Context, id kri.ID, p kri.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	h := PolicyHash(p)
	if h == s.PolicyHash {
		return nil
	}
	g := s.Gateway
	want := map[string]kri.Credential{}
	for _, c := range p.Credentials {
		want[ProfileID(id, c)] = c
	}
	for name, c := range want {
		ver, have := s.Providers[name]
		if have && ver == c.Version {
			continue
		}
		env := []string{c.Env + "=" + string(c.Value)}
		if !have {
			prof := StateDir + "/policies/" + name + ".profile.yaml"
			if err := r.Host.WriteFile(prof, []byte(ProfileYAML(id, c)), 0o600); err != nil {
				return err
			}
			if _, err := r.cli(ctx, g, nil, nil, "profile", "import", "-f", prof); err != nil && !strings.Contains(err.Error(), "exists") {
				return err
			}
			if _, err := r.cli(ctx, g, nil, env, "provider", "create", "--name", name, "--type", name, "--credential", c.Env); err != nil {
				if !strings.Contains(err.Error(), "exists") {
					return err
				}
				if _, err := r.cli(ctx, g, nil, env, "provider", "update", name, "--credential", c.Env, "--wait"); err != nil {
					return err
				}
			}
			if s.Created {
				if _, err := r.cli(ctx, g, nil, nil, "sandbox", "provider", "attach", SandboxName(id), name); err != nil && !strings.Contains(err.Error(), "already") {
					return err
				}
			}
		} else if _, err := r.cli(ctx, g, nil, env, "provider", "update", name, "--credential", c.Env, "--wait"); err != nil {
			return err // a rotation: the next request carries the new value (E037)
		}
		s.Providers[name] = c.Version
	}
	for name := range s.Providers {
		if _, ok := want[name]; ok {
			continue
		}
		if s.Created {
			_, _ = r.cli(ctx, g, nil, nil, "sandbox", "provider", "detach", SandboxName(id), name)
		}
		_, _ = r.cli(ctx, g, nil, nil, "provider", "delete", name)
		_, _ = r.cli(ctx, g, nil, nil, "profile", "delete", name)
		delete(s.Providers, name)
	}
	if err := r.Host.WriteFile(policyPath(id), []byte(PolicyYAML(p)), 0o600); err != nil {
		return err
	}
	if s.Created {
		if _, err := r.cli(ctx, g, nil, nil, "policy", "set", SandboxName(id), "--policy", policyPath(id), "--yes", "--wait"); err != nil {
			return err
		}
	}
	s.PolicyHash = h
	return r.save(s)
}

var (
	_ kri.Runtime  = (*Runtime)(nil)
	_ kri.Policied = (*Runtime)(nil)
)

// ErrNoKVM: the VM driver needs /dev/kvm.
var ErrNoKVM = errors.New("openshell: the VM driver needs /dev/kvm (use openshell-container on hosts without KVM)")
