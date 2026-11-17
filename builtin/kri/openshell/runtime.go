package openshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	ID      kri.ID  `json:"id"`
	Gateway Gateway `json:"gateway"`
	Image   string  `json:"image,omitempty"`
	CPU     int     `json:"cpu"`
	Memory  int64   `json:"memory"`
	Created bool    `json:"created"` // the sandbox exists in OpenShell
	Running bool    `json:"running"` // Kevaso started it and hasn't stopped it: its gateway stays up
	// Deleted: Delete ran while its gateway was down. The silo is gone for Kevaso; the gateway's
	// part (the sandbox, the providers) is done at the next claimed Start on that gateway.
	Deleted bool `json:"deleted,omitempty"`
	// ResetPending: Reset ran while its gateway was down; its next (claimed) Start removes the old
	// sandbox before it makes a fresh one.
	ResetPending bool `json:"resetPending,omitempty"`
	// Boot is the host's boot when Kevaso last started it: Running from an earlier boot isn't a
	// start of this one (no claim of it applied since the reboot).
	Boot       string           `json:"boot,omitempty"`
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
	s, ok := r.loadAny(id)
	if !ok || s.Deleted {
		return state{}, false
	}
	return s, true
}

// loadAny is load with a record deleted while its gateway was down (Deleted) too.
func (r *Runtime) loadAny(id kri.ID) (state, bool) {
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

// statesReadable reads every silo state on this host. A file that cannot be listed, read, or
// understood is not "no silo": a delete must not treat a neighbour it cannot see as absent.
func (r *Runtime) statesReadable() error {
	paths, err := r.Host.Glob(StateDir + "/silos/*.json")
	if err != nil {
		return fmt.Errorf("silo states could not be listed: %w", err)
	}
	for _, p := range paths {
		b, err := r.Host.ReadFile(p)
		if err != nil {
			return fmt.Errorf("silo state %s could not be read: %w", p, err)
		}
		var s state
		if json.Unmarshal(b, &s) != nil || s.ID.UID == "" {
			return fmt.Errorf("silo state %s could not be read", p)
		}
	}
	return nil
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
	persistence := PersistenceWorkspace // a stopped sandbox stays stopped with its files (seen on both drivers)
	return kri.Info{Name: r.Name, Version: Version, Capabilities: kri.Capabilities{
		Isolation: iso, Network: "proxy", UDP: false, InboundServices: false, Persistence: persistence, Injection: true, Exec: true,
	}}
}

// ── gateways ─────────────────────────────────────────────────────────────────

const gatewaysFile = StateDir + "/gateways.json"

// prepare finds or readies the gateway for key: its port, user, directories, config and
// locked-down unit. It starts nothing: Create runs before the agent's start claim, and a gateway
// that starts brings back what its record says ran.
func (r *Runtime) prepare(ctx context.Context, key string) (Gateway, error) {
	gws := map[string]Gateway{}
	b, err := r.Host.ReadFile(gatewaysFile)
	if err == nil {
		err = json.Unmarshal(b, &gws)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// Its gateways' ports are unknown: a new one could be given a port one of them listens on,
		// and the file written over would forget them all (K-105's shape).
		return Gateway{}, fmt.Errorf("%s can't be read (%v): no gateway is readied on this host until it is restored", gatewaysFile, err)
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
	if u, err := r.Host.ReadFile(unitPath(g)); err == nil && string(u) == g.UnitFile() {
		return g, nil // readied before
	}
	if err := r.setupGateway(ctx, g); err != nil {
		return g, fmt.Errorf("gateway %s: %w", g.Key, err)
	}
	return g, nil
}

func unitPath(g Gateway) string { return "/etc/systemd/system/" + g.Unit() }

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
	if err := r.Host.WriteFile(unitPath(g), []byte(g.UnitFile()), 0o644); err != nil {
		return err
	}
	return r.run(ctx, "systemctl", "daemon-reload")
}

// up makes sure gateway g answers. It is called only from a silo's claimed Start (self): every
// other caller (Delete, Reset, a policy change, an exec) answers from what runs and never starts
// a gateway. A gateway that starts brings back the sandboxes its record says ran, its neighbours
// too: before up returns, every sandbox on it but self is confirmed stopped (review-batch4 claim
// 4), and if that can't be confirmed (the context ended during the wait, a stop that didn't
// take) the gateway is stopped again and up fails. The same holds for a unit found already
// coming up (activating), which brought back the same.
func (r *Runtime) up(ctx context.Context, g Gateway, self kri.ID) error {
	if _, err := r.prepare(ctx, g.Key); err != nil {
		return err
	}
	if r.answers(ctx, g) {
		r.finishDeletes(ctx, g) // up and registered: its neighbours were settled when it came up
		return nil
	}
	active, err := r.unitActive(ctx, g)
	if err != nil {
		return err
	}
	if active { // coming up, or running and not registered: registered once more if need be, else silent
		_, err := r.cli(ctx, g, nil, nil, "gateway", "add", g.Endpoint(), "--local", "--name", g.Name())
		if err != nil && !strings.Contains(err.Error(), "already") || !r.answers(ctx, g) {
			return fmt.Errorf("gateway %s: %w", g.Key, ErrGatewaySilent)
		}
		// Nothing tells what of it ran before: only a silo Kevaso started and hasn't stopped is
		// kept running; every other is settled as after a start.
		keep := func(o *state) bool { return o != nil && r.startedThisBoot(*o) }
		return r.settled(ctx, g, self, keep)
	}
	before, err := r.runningContainers(ctx, g) // what ran before the start (the Docker driver's containers)
	if err != nil {
		return err
	}
	keep := func(o *state) bool { return o != nil && before[SandboxName(o.ID)] }
	if err := r.run(ctx, "systemctl", "start", g.Unit()); err != nil {
		return errors.Join(fmt.Errorf("gateway %s: %w", g.Key, err), r.stopAgain(ctx, g, self, keep))
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
				break
			}
		}
		last = err
		if time.Now().After(deadline) || ctx.Err() != nil {
			// What it brought back can't be stopped through it: the gateway is stopped again.
			return errors.Join(fmt.Errorf("gateway %s never answered: %w", g.Key, last), r.stopAgain(ctx, g, self, keep))
		}
		r.sleep(3 * time.Second)
	}
	return r.settled(ctx, g, self, keep)
}

// settled stops every sandbox on gateway g but self and those keep says ran before, confirms
// that nothing of them runs, and finishes the deletes made while it was down. If any of it fails,
// the gateway is stopped again and the error returned: no sandbox runs on a gateway that came up
// without its own claim.
func (r *Runtime) settled(ctx context.Context, g Gateway, self kri.ID, keep func(*state) bool) error {
	if err := r.stopNeighbours(ctx, g, self, keep); err != nil {
		return errors.Join(fmt.Errorf("gateway %s: what it brought back isn't confirmed stopped: %w", g.Key, err), r.stopAgain(ctx, g, self, keep))
	}
	r.finishDeletes(ctx, g)
	return nil
}

// stopNeighbours stops, then confirms stopped by looking, every sandbox the gateway lists (and,
// for the Docker driver, every container of a sandbox of g) but self and those kept: by the
// gateway's own list, so a sandbox Kevaso has no record of (or one deleted while it was down) is
// stopped too.
func (r *Runtime) stopNeighbours(ctx context.Context, g Gateway, self kri.ID, keep func(*state) bool) error {
	records := map[string]*state{}
	for _, o := range r.all() {
		if o.Gateway.Key == g.Key {
			records[SandboxName(o.ID)] = &o
		}
	}
	other := func(name string) bool { return name != SandboxName(self) && !keep(records[name]) }
	for pass := 0; ; pass++ {
		out, err := r.cli(ctx, g, nil, nil, "sandbox", "list", "-o", "json")
		if err != nil {
			return err
		}
		phases, err := sandboxPhases(out)
		if err != nil {
			return err
		}
		var running []string
		for name, phase := range phases {
			if other(name) && Phase(phase) != kri.Stopped {
				running = append(running, name)
			}
		}
		var containers []string
		if g.Driver == DriverDocker {
			c, err := r.runningContainers(ctx, g)
			if err != nil {
				return err
			}
			for name := range c {
				if other(name) {
					containers = append(containers, name)
				}
			}
		}
		if len(running) == 0 && len(containers) == 0 {
			return nil
		}
		if pass > 0 {
			sort.Strings(running)
			sort.Strings(containers)
			return fmt.Errorf("still running after their stop: %v (containers %v)", running, containers)
		}
		sort.Strings(running)
		for _, name := range running {
			if _, err := r.cli(ctx, g, nil, nil, "sandbox", "stop", name); err != nil {
				return err
			}
		}
		for _, name := range containers {
			if err := r.stopContainers(ctx, state{ID: records[name].ID, Gateway: g}); err != nil {
				return err
			}
		}
	}
}

// stopAgain stops gateway g after an up that failed, whatever the caller's context (it may be
// what ended), and the Docker driver's containers of its sandboxes but those kept; it says what
// it couldn't.
func (r *Runtime) stopAgain(ctx context.Context, g Gateway, self kri.ID, keep func(*state) bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	var errs []error
	if err := r.run(ctx, "systemctl", "stop", g.Unit()); err != nil {
		errs = append(errs, err)
	} else if active, err := r.unitActive(ctx, g); err != nil || active {
		errs = append(errs, fmt.Errorf("gateway %s: still active after its stop (%v)", g.Key, err))
	}
	for _, o := range r.all() {
		if o.Gateway.Key == g.Key && (o.ID == self || !keep(&o)) && g.Driver == DriverDocker {
			if err := r.stopContainers(ctx, o); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("stopping gateway %s again: %w", g.Key, err)
	}
	return nil
}

// sandboxPhases reads `sandbox list -o json` as sandbox name → phase (sandboxNames' two forms).
func sandboxPhases(out []byte) (map[string]string, error) {
	var list []sandboxJSON
	if err := json.Unmarshal(out, &list); err != nil {
		var obj struct {
			Sandboxes *[]sandboxJSON `json:"sandboxes"`
		}
		if json.Unmarshal(out, &obj) != nil || obj.Sandboxes == nil {
			return nil, fmt.Errorf("sandbox list: not a list: %.80q", out)
		}
		list = *obj.Sandboxes
	}
	phases := map[string]string{}
	for _, sb := range list {
		phases[sb.Name] = sb.Phase
	}
	return phases, nil
}

// finishDeletes does the gateway's part of the deletes made while gateway g was down: each
// sandbox removed, its providers revoked, then its record. One that fails stays recorded and is
// tried again at the next start on g: it never fails that start (K-116: one stuck delete held
// every start on its gateway). Its sandbox is stopped already: settled stops every sandbox but
// the one starting, and a deleted one is never kept.
func (r *Runtime) finishDeletes(ctx context.Context, g Gateway) {
	for _, o := range r.all() {
		if o.Gateway.Key != g.Key || !o.Deleted {
			continue
		}
		if r.deleteInGateway(ctx, &o) != nil {
			continue
		}
		_ = r.Host.RemoveAll(policyPath(o.ID))
		_ = r.Host.RemoveAll(statePath(o.ID))
	}
}

// down stops gateway g when none of its sandboxes should run (except is the one just stopped or
// deleted), and checks that its unit is down: with KillMode=control-group, nothing of the VM
// driver's sandboxes outlives it.
func (r *Runtime) down(ctx context.Context, g Gateway, except kri.ID) error {
	for _, o := range r.all() {
		if o.Gateway.Key == g.Key && o.ID != except && o.Running {
			return nil // a neighbour runs on it
		}
	}
	if err := r.run(ctx, "systemctl", "stop", g.Unit()); err != nil {
		return err
	}
	if active, err := r.unitActive(ctx, g); err != nil || active {
		return fmt.Errorf("gateway %s: still active after its stop (%v)", g.Key, err)
	}
	return nil
}

// unitActive asks systemd whether g's unit is active, by its exact answer. Anything but
// inactive or failed (activating, deactivating, reloading) counts as active: it may run.
func (r *Runtime) unitActive(ctx context.Context, g Gateway) (bool, error) {
	var out bytes.Buffer
	_, err := r.Host.Run(ctx, Cmd{Name: "systemctl", Args: []string{"is-active", g.Unit()}, Stdout: &out, Stderr: io.Discard})
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w", g.Unit(), err)
	}
	switch st := strings.TrimSpace(out.String()); st {
	case "inactive", "failed":
		return false, nil
	case "":
		return false, fmt.Errorf("systemctl is-active %s: no answer", g.Unit())
	default:
		return true, nil
	}
}

// runningContainers are the Docker driver's running containers of g's sandboxes, by sandbox name
// (empty for the VM driver, whose sandboxes are processes of the unit). The containers are found
// by their names containing the sandbox's (kv- and ten hex digits): to be checked on a machine.
func (r *Runtime) runningContainers(ctx context.Context, g Gateway) (map[string]bool, error) {
	out := map[string]bool{}
	if g.Driver != DriverDocker {
		return out, nil
	}
	var b bytes.Buffer
	code, err := r.Host.Run(ctx, Cmd{Name: "docker", Args: []string{"ps", "--format", "{{.Names}}"}, Stdout: &b, Stderr: io.Discard})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	names := strings.Fields(b.String())
	for _, s := range r.all() {
		if s.Gateway.Key != g.Key {
			continue
		}
		for _, n := range names {
			if strings.Contains(n, SandboxName(s.ID)) {
				out[SandboxName(s.ID)] = true
			}
		}
	}
	return out, nil
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
	g, err := r.prepare(ctx, GatewayKey(r.Driver, r.scope(), spec.ID))
	if err != nil {
		return err
	}
	if err := r.run(ctx, "install", "-d", "-m", "0700", StateDir+"/silos", StateDir+"/policies"); err != nil {
		return err
	}
	s := state{ID: spec.ID, Gateway: g, Image: spec.Image, CPU: spec.CPU, Memory: spec.Memory, Providers: map[string]int64{}}
	if old, ok := r.loadAny(spec.ID); ok && old.Deleted && old.Gateway.Key == g.Key {
		// Made again over a delete whose gateway part isn't done (K-116): the old sandbox, if its
		// gateway still has it, is removed at the first start (never started with its data),
		// and its providers stay known, to be revoked by the next policy.
		s.ResetPending, s.Providers = old.Created || old.ResetPending, old.Providers
	}
	// Deny-all until the agent stages the silo's grants (StagePolicy), which it does before Start
	// creates the sandbox. A silo with no grants stays this file: nothing outside.
	if err := r.Host.WriteFile(policyPath(spec.ID), []byte(basePolicy), 0o600); err != nil {
		return err
	}
	return r.save(s)
}

// StagePolicy writes the policy file the next sandbox create is given (--policy). It does not
// push it onto a sandbox that already exists, and it does not record the policy as applied.
// The gateway does not need to be up: the file is on the host.
func (r *Runtime) StagePolicy(ctx context.Context, id kri.ID, p kri.Policy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.load(id); !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	for _, c := range p.Credentials {
		if err := CheckCredential(c); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return r.Host.WriteFile(policyPath(id), []byte(PolicyYAML(p)), 0o600)
}

func policyPath(id kri.ID) string { return StateDir + "/policies/" + Short(id) + ".yaml" }

type sandboxJSON struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Phase  string            `json:"phase"`
	Labels map[string]string `json:"labels"`
}

// get asks s's gateway for its sandbox. "Not there" is decided by an exact answer only: the
// gateway's own list, parsed, without it (K-101: an error saying "not found" may be about the
// gateway, not the sandbox). Anything else that fails is an error.
func (r *Runtime) get(ctx context.Context, s state) (sandboxJSON, bool, error) {
	out, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "get", SandboxName(s.ID), "-o", "json")
	if err == nil {
		var sb sandboxJSON
		if err := json.Unmarshal(out, &sb); err != nil {
			return sandboxJSON{}, false, fmt.Errorf("sandbox get: %w", err)
		}
		return sb, true, nil
	}
	list, lerr := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "list", "-o", "json")
	if lerr != nil {
		return sandboxJSON{}, false, err
	}
	names, perr := sandboxNames(list)
	if perr != nil {
		return sandboxJSON{}, false, fmt.Errorf("%w (and its list: %v)", err, perr)
	}
	if names[SandboxName(s.ID)] {
		return sandboxJSON{}, false, err // listed, and get failed: not "gone"
	}
	return sandboxJSON{}, false, nil
}

// sandboxNames reads `sandbox list -o json`: an array of sandboxes, or an object holding one
// under "sandboxes" (which of the two v0.1.8 prints is to be checked on a machine).
func sandboxNames(out []byte) (map[string]bool, error) {
	var list []sandboxJSON
	if err := json.Unmarshal(out, &list); err != nil {
		var obj struct {
			Sandboxes *[]sandboxJSON `json:"sandboxes"`
		}
		if json.Unmarshal(out, &obj) != nil || obj.Sandboxes == nil {
			return nil, fmt.Errorf("sandbox list: not a list: %.80q", out)
		}
		list = *obj.Sandboxes
	}
	names := map[string]bool{}
	for _, sb := range list {
		names[sb.Name] = true
	}
	return names, nil
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
	if err := r.up(ctx, s.Gateway, id); err != nil { // e.g. after a host reboot
		return err
	}
	s.Running, s.Boot = true, r.boot() // before the start: a gateway with a sandbox that may run stays up
	if err := r.save(s); err != nil {
		return err
	}
	sb, exists, err := r.get(ctx, s)
	if err != nil {
		return err
	}
	if s.ResetPending { // a reset made while its gateway was down: the old sandbox goes first
		if exists {
			if err := r.removeSandbox(ctx, s); err != nil {
				return err
			}
		}
		s.ResetPending, s.Created, exists = false, false, false
		if err := r.save(s); err != nil {
			return err
		}
	}
	if exists {
		if Phase(sb.Phase) == kri.Failed {
			// Seen on the VM driver: a gateway started again brings the sandbox's VM back itself,
			// then marks it Error ("already running") and refuses start. A stop clears that.
			if _, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "stop", SandboxName(id)); err != nil {
				return err
			}
		}
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

// Stop implements kri.Runtime: after it returns, nothing of the sandbox runs, by looking (the VM
// driver's unit down, or the gateway's phase while a neighbour keeps it up; the Docker driver's
// containers), not by the gateway's word. The last sandbox of its gateway that should run takes
// the gateway down with it (item 1), so nothing of OpenShell runs for a host whose silos are all
// stopped, and nothing starts it again but a silo's claimed Start.
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	s.Running = false
	if err := r.save(s); err != nil {
		return err
	}
	g := s.Gateway
	if s.Created {
		if !r.answers(ctx, g) {
			active, err := r.unitActive(ctx, g)
			if err != nil {
				return err
			}
			if active {
				return fmt.Errorf("%s: stop: %w", id, ErrGatewaySilent)
			}
		} else {
			sb, exists, err := r.get(ctx, s)
			if err != nil {
				return err
			}
			if exists && Phase(sb.Phase) != kri.Stopped {
				if _, err := r.cli(ctx, g, nil, nil, "sandbox", "stop", SandboxName(id)); err != nil {
					return err
				}
			}
		}
	}
	if err := r.down(ctx, g, id); err != nil {
		return err
	}
	return r.stopped(ctx, s)
}

// boot is the host's boot id ("" if it can't be read).
func (r *Runtime) boot() string {
	b, err := r.Host.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// startedThisBoot: Kevaso started s (after its claim) in this boot of the host and hasn't
// stopped it since: what a gateway found already coming up may keep running (up). It is no claim
// and brings no gateway up (it outlives a kevasod restart).
func (r *Runtime) startedThisBoot(s state) bool {
	b := r.boot()
	return s.Running && b != "" && s.Boot == b
}

// answers: gateway g answers the CLI.
func (r *Runtime) answers(ctx context.Context, g Gateway) bool {
	_, err := r.cli(ctx, g, nil, nil, "sandbox", "list", "-o", "json")
	return err == nil
}

// removeSandbox deletes s's sandbox and confirms it is gone.
func (r *Runtime) removeSandbox(ctx context.Context, s state) error {
	if _, err := r.cli(ctx, s.Gateway, nil, nil, "sandbox", "delete", SandboxName(s.ID)); err != nil {
		return err
	}
	_, exists, err := r.get(ctx, s)
	if err == nil && exists {
		err = fmt.Errorf("%s: still in OpenShell after its delete", SandboxName(s.ID))
	}
	return err
}

// stopped checks by looking that nothing of s's sandbox runs. A Docker-driver container still up
// (its gateway down, or a gateway that said Stopped) is stopped here, by name.
func (r *Runtime) stopped(ctx context.Context, s state) error {
	runs, err := r.runs(ctx, s)
	if err != nil || !runs {
		return err
	}
	if s.Gateway.Driver == DriverDocker {
		if err := r.stopContainers(ctx, s); err != nil {
			return err
		}
		if runs, err = r.runs(ctx, s); err != nil || !runs {
			return err
		}
	}
	return fmt.Errorf("%s: still runs after its stop", s.ID)
}

// runs looks whether anything of s's sandbox runs: the Docker driver's containers; for the VM
// driver, its unit (down: nothing of it runs), else the gateway's phase (what a neighbour's
// running gateway leaves to look at).
func (r *Runtime) runs(ctx context.Context, s state) (bool, error) {
	if s.Gateway.Driver == DriverDocker {
		c, err := r.runningContainers(ctx, s.Gateway)
		return c[SandboxName(s.ID)], err
	}
	active, err := r.unitActive(ctx, s.Gateway)
	if err != nil || !active {
		return false, err
	}
	if !s.Created {
		return false, nil
	}
	sb, exists, err := r.get(ctx, s)
	if err != nil {
		return false, fmt.Errorf("%s: %w (%v)", s.ID, ErrGatewaySilent, err)
	}
	return exists && Phase(sb.Phase) != kri.Stopped, nil
}

// removeContainers removes the Docker driver's containers of every sandbox of g (only: of that
// silo's alone), running or not, by name (they carry OpenShell's labels, not Kevaso's: their
// names contain the sandbox's, seen on the machines).
func (r *Runtime) removeContainers(ctx context.Context, g Gateway, only *kri.ID) error {
	if g.Driver != DriverDocker {
		return nil
	}
	var b bytes.Buffer
	code, err := r.Host.Run(ctx, Cmd{Name: "docker", Args: []string{"ps", "-a", "--format", "{{.Names}}"}, Stdout: &b, Stderr: io.Discard})
	if err == nil && code != 0 {
		err = fmt.Errorf("exit %d", code)
	}
	if err != nil {
		return fmt.Errorf("docker ps -a: %w", err)
	}
	var names []string
	for _, n := range strings.Fields(b.String()) {
		for _, o := range r.all() {
			if o.Gateway.Key == g.Key && (only == nil || o.ID == *only) && strings.Contains(n, SandboxName(o.ID)) {
				names = append(names, n)
				break
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	return r.run(ctx, "docker", append([]string{"rm", "-f"}, names...)...)
}

// stopContainers stops the Docker driver's running containers of s's sandbox, by name.
func (r *Runtime) stopContainers(ctx context.Context, s state) error {
	var b bytes.Buffer
	if _, err := r.Host.Run(ctx, Cmd{Name: "docker", Args: []string{"ps", "--format", "{{.Names}}"}, Stdout: &b, Stderr: io.Discard}); err != nil {
		return err
	}
	var names []string
	for _, n := range strings.Fields(b.String()) {
		if strings.Contains(n, SandboxName(s.ID)) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return r.run(ctx, "docker", append([]string{"stop"}, names...)...)
}

// Delete implements kri.Runtime: the sandbox, its providers and profiles, its state; with the
// last sandbox of its gateway, the gateway too (unit, user, home with its registration and
// credential store, port). It never starts the gateway (only a silo's claimed Start does):
//   - Gateway answering: removed through it, each step confirmed (K-080).
//   - Gateway running and silent: the error, nothing removed.
//   - Gateway down, and this the last silo on it: the gateway goes whole, with no word of it
//     needed (its home holds the VM disks, its records and its credential store); the Docker
//     driver's containers go by name.
//   - Gateway down, neighbours left: its containers go by name, and its sandbox and providers
//     are removed at the next claimed Start on that gateway (stopped first, as every sandbox a
//     gateway brings back). The delete is done for Kevaso and the silo no longer listed (K-116:
//     it used to wait for a neighbour's start, which a stopped neighbour never makes): nothing
//     of it can run meanwhile, since only a claimed Start brings the gateway up, and that stops it.
func (r *Runtime) Delete(ctx context.Context, id kri.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.loadAny(id)
	if !ok {
		return nil
	}
	s.Running = false
	if err := r.save(s); err != nil {
		return err
	}
	if err := r.statesReadable(); err != nil {
		return fmt.Errorf("%s: delete: %w", id, err)
	}
	g := s.Gateway
	last := true
	for _, o := range r.all() {
		if o.Gateway.Key == g.Key && o.ID != id && !o.Deleted {
			last = false
		}
	}
	reach, err := r.reachable(ctx, g)
	if err != nil {
		return fmt.Errorf("%s: delete: %w", id, err)
	}
	switch {
	case reach:
		if err := r.deleteInGateway(ctx, &s); err != nil {
			return err
		}
	case !last:
		// The Docker driver's containers may outlive a gateway that crashed: they go now, by name.
		if err := r.removeContainers(ctx, g, &id); err != nil {
			return err
		}
		if runs, err := r.runs(ctx, s); err != nil || runs {
			return fmt.Errorf("%s: delete: still runs with its gateway down (%v)", id, err)
		}
		// Its sandbox (the VM driver's disk, the gateway's record, its providers) stays in the
		// gateway's home until a neighbour's claimed Start brings the gateway up, which stops it
		// before anything else and then removes it (finishDeletes). For Kevaso the delete is done
		// (K-116): nothing of it can run, and the gateway, with its neighbours, is never started
		// for a delete. It is no longer listed.
		s.Deleted = true
		return r.save(s)
	}
	if !last {
		_ = r.Host.RemoveAll(policyPath(id))
		if err := r.Host.RemoveAll(statePath(id)); err != nil {
			return err
		}
		return r.down(ctx, g, id) // a neighbour keeps it
	}
	if err := r.removeGateway(ctx, g); err != nil {
		return err
	}
	for _, o := range r.all() { // this silo, and deletes left for a start that won't come now
		if o.Gateway.Key == g.Key {
			_ = r.Host.RemoveAll(policyPath(o.ID))
			for p := range o.Providers {
				_ = r.Host.RemoveAll(StateDir + "/policies/" + p + ".profile.yaml")
			}
			if err := r.Host.RemoveAll(statePath(o.ID)); err != nil {
				return err
			}
		}
	}
	return nil
}

// reachable: gateway g answers (true), is down (false), or runs and doesn't answer (an error
// wrapping ErrGatewaySilent).
func (r *Runtime) reachable(ctx context.Context, g Gateway) (bool, error) {
	if r.answers(ctx, g) {
		return true, nil
	}
	active, err := r.unitActive(ctx, g)
	if err != nil {
		return false, err
	}
	if active {
		return false, fmt.Errorf("gateway %s: %w", g.Key, ErrGatewaySilent)
	}
	return false, nil
}

// deleteInGateway removes s's sandbox and providers through its answering gateway, each step
// confirmed before it is forgotten.
func (r *Runtime) deleteInGateway(ctx context.Context, s *state) error {
	if s.Created {
		_, exists, err := r.get(ctx, *s)
		if err != nil {
			return err
		}
		if exists {
			if err := r.removeSandbox(ctx, *s); err != nil {
				return err
			}
		}
		s.Created = false
		if err := r.save(*s); err != nil {
			return err
		}
	}
	names := make([]string, 0, len(s.Providers))
	for p := range s.Providers {
		names = append(names, p)
	}
	sort.Strings(names)
	return r.revoke(ctx, s, names)
}

// revoke takes providers names of s out of its gateway: detached from the sandbox, deleted with
// their profiles, each forgotten only once its gateway confirmed it (K-080: a revoke that can't
// be told is not done, and is tried again). A provider deleted whose profile isn't yet is kept
// as version -1.
func (r *Runtime) revoke(ctx context.Context, s *state, names []string) error {
	g := s.Gateway
	for _, name := range names {
		if s.Providers[name] >= 0 {
			if s.Created {
				if _, err := r.cli(ctx, g, nil, nil, "sandbox", "provider", "detach", SandboxName(s.ID), name); err != nil {
					return fmt.Errorf("%s: revoke %s: %w", s.ID, name, err)
				}
			}
			if _, err := r.cli(ctx, g, nil, nil, "provider", "delete", name); err != nil {
				return fmt.Errorf("%s: revoke %s: %w", s.ID, name, err)
			}
			s.Providers[name] = -1
			if err := r.save(*s); err != nil {
				return err
			}
		}
		if _, err := r.cli(ctx, g, nil, nil, "profile", "delete", name); err != nil {
			return fmt.Errorf("%s: revoke %s: %w", s.ID, name, err)
		}
		_ = r.Host.RemoveAll(StateDir + "/policies/" + name + ".profile.yaml")
		delete(s.Providers, name)
		if err := r.save(*s); err != nil {
			return err
		}
	}
	return nil
}

// removeGateway takes gateway g off the host once its last sandbox is gone: its unit, user, home
// (the CLI's registration and its credential store), and its port.
func (r *Runtime) removeGateway(ctx context.Context, g Gateway) error {
	if err := r.run(ctx, "systemctl", "stop", g.Unit()); err != nil {
		return err
	}
	if active, err := r.unitActive(ctx, g); err != nil || active {
		return fmt.Errorf("gateway %s: still active after its stop (%v)", g.Key, err)
	}
	if err := r.removeContainers(ctx, g, nil); err != nil {
		return err
	}
	if err := r.Host.RemoveAll(unitPath(g)); err != nil {
		return err
	}
	if err := r.run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if r.run(ctx, "id", "-u", g.User()) == nil {
		if err := r.run(ctx, "userdel", g.User()); err != nil {
			return err
		}
	}
	if err := r.Host.RemoveAll(g.Dir()); err != nil {
		return err
	}
	gws := map[string]Gateway{}
	b, err := r.Host.ReadFile(gatewaysFile)
	if err == nil {
		err = json.Unmarshal(b, &gws)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s can't be read (%v): not written over, the other gateways' ports would be forgotten", gatewaysFile, err)
	}
	delete(gws, g.Key)
	b, _ = json.MarshalIndent(gws, "", "  ")
	return r.Host.WriteFile(gatewaysFile, b, 0o600)
}

// Reset implements kri.Resetter: the sandbox goes (its gateway and providers stay) and is made
// again from spec's image on Start, with the policy applied afresh.
func (r *Runtime) Reset(ctx context.Context, spec kri.Spec) error {
	return r.ResetGated(ctx, spec, nil)
}

// ResetGated is Reset that asks gate (if set) right before the sandbox is deleted. An error from
// gate ends the reset with nothing deleted, and is returned as is.
func (r *Runtime) ResetGated(ctx context.Context, spec kri.Spec, gate func(context.Context) error) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.load(spec.ID)
	if !ok {
		return fmt.Errorf("%s: %w", spec.ID, kri.ErrNotFound)
	}
	// The silo is stopped, so its gateway may be down (item 1). It isn't started for this (only a
	// claimed Start does): the old sandbox then goes at the next Start, before the fresh one.
	exists, reach := false, false
	if s.Created {
		if reach, err = r.reachable(ctx, s.Gateway); err != nil {
			return err
		}
		if reach {
			if _, exists, err = r.get(ctx, s); err != nil {
				return err
			}
		}
	}
	if gate != nil {
		if err := gate(ctx); err != nil {
			return err
		}
	}
	if exists {
		if err := r.removeSandbox(ctx, s); err != nil {
			return err
		}
	}
	s.ResetPending = s.Created && !reach
	s.Image, s.CPU, s.Memory, s.Created, s.PolicyHash = spec.Image, spec.CPU, spec.Memory, false, ""
	return r.save(s)
}

// Status implements kri.Runtime. Running, Stopped and unknown are told apart (K-101): with its
// gateway answering, the sandbox's phase (a sandbox its gateway lists no more is Failed); with
// its gateway's unit down, the look (the VM driver's sandbox can't run, Stopped; the Docker
// driver's container may run on under dockerd, Running if it does); with its gateway running and
// not answering, unknown: an error wrapping ErrGatewaySilent.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	s, ok := r.load(id)
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	if !s.Created {
		return kri.Status{State: kri.Created}, nil
	}
	sb, exists, err := r.get(ctx, s)
	if err == nil {
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
	active, aerr := r.unitActive(ctx, s.Gateway)
	if aerr != nil {
		return kri.Status{}, fmt.Errorf("%s: %w (%v; %v)", id, ErrGatewaySilent, firstLine(err.Error()), aerr)
	}
	if active {
		return kri.Status{}, fmt.Errorf("%s: %w: %s", id, ErrGatewaySilent, firstLine(err.Error()))
	}
	down := "its gateway " + s.Gateway.Name() + " is down"
	runs, rerr := r.runs(ctx, s)
	if rerr != nil {
		return kri.Status{}, fmt.Errorf("%s: %s, and its containers can't be seen: %w", id, down, rerr)
	}
	if runs {
		return kri.Status{State: kri.Running, Message: down + "; its container runs on"}, nil
	}
	return kri.Status{State: kri.Stopped, Message: down + ": nothing of it runs"}, nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// List implements kri.Runtime.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	var ids []kri.ID
	for _, s := range r.all() {
		if !s.Deleted { // deleted for Kevaso: what its gateway holds of it goes at the gateway's next start
			ids = append(ids, s.ID)
		}
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
	// Never starts its gateway (only a claimed Start does): down, the silo isn't running for an
	// exec, whatever ran on (review-batch4 claim 4).
	if reach, err := r.reachable(ctx, s.Gateway); err != nil {
		return -1, err
	} else if !reach {
		return -1, fmt.Errorf("%s is not running for an exec: its gateway %s is down (only its claimed start brings it up)", id, s.Gateway.Name())
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
	// The command runs under a shell holding a marker (hostexec.Held: on its command line, and in
	// the command's environment), so that when the client goes away whatever it started is swept
	// inside the sandbox, even if it cleared its environment: killing the CLI isn't known to stop
	// it. With a terminal the CLI runs on one of the agent's own and picks the sandbox's terminal
	// itself (no --no-tty).
	marker := hostexec.NewMarker()
	args := []string{"sandbox", "exec", "-n", SandboxName(id)}
	if req.TTY == nil {
		args = append(args, "--no-tty")
	}
	args = append(append(args, "--"), hostexec.Held(marker, req.Command)...)
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
func (r *Runtime) SetPolicy(ctx context.Context, id kri.ID, p kri.Policy) (err error) {
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
		if err := CheckCredential(c); err != nil { // before anything is written or run (K-066)
			return fmt.Errorf("%s: %w", id, err)
		}
		want[ProfileID(id, c)] = c
	}
	// The providers live in the gateway's store: it must answer. A policy change never brings it
	// back (only a claimed Start does, review-batch4 claim 4: the Running flag outlives a kevasod
	// restart, and isn't a claim): with its gateway down, the policy waits for the silo's next
	// start (the agent applies it after Start).
	if reach, err := r.reachable(ctx, g); err != nil {
		return err
	} else if !reach {
		return fmt.Errorf("%s: policy: its gateway %s is down (the silo isn't running): applied at its next start", id, g.Name())
	}
	for name, c := range want {
		ver, have := s.Providers[name]
		have = have && ver >= 0 // -1: deleted, its profile not yet
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
	var gone []string
	for name := range s.Providers {
		if _, ok := want[name]; !ok {
			gone = append(gone, name)
		}
	}
	sort.Strings(gone)
	if err := r.revoke(ctx, &s, gone); err != nil {
		return err
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
	_ kri.Runtime      = (*Runtime)(nil)
	_ kri.Policied     = (*Runtime)(nil)
	_ kri.PolicyStager = (*Runtime)(nil)
)

// ErrNoKVM: the VM driver needs /dev/kvm.
var ErrNoKVM = errors.New("openshell: the VM driver needs /dev/kvm (use openshell-container on hosts without KVM)")

// ErrGatewaySilent: the silo's gateway runs (its unit is up) and doesn't answer, so nothing can
// say whether its sandbox runs, or stop it through the gateway. Status returns it for "unknown".
var ErrGatewaySilent = errors.New("its OpenShell gateway runs and doesn't answer: whether the sandbox runs is unknown")

// PersistenceWorkspace is the capabilities' persistence: the sandbox's files are kept across a
// stop (a gateway that starts leaves a Stopped sandbox stopped, seen on both drivers).
const PersistenceWorkspace = "workspace"
