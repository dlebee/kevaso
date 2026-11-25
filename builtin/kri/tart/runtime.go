// Package tart is the macOS runtime: a silo is a macOS virtual machine on an Apple Silicon Mac,
// driven through the `tart` command line program that the operator installs (Tart is licensed
// FSL-1.1-ALv2; Kevaso only runs it as a separate program, and none of its code is here).
//
// The shape follows research E038-E042 (kevaso-research):
//   - Image: an OCI reference to a macOS image (container.image), pulled once on the host and
//     cloned per silo (APFS clone: instant, shares blocks).
//   - Ready is "the first exec answers", not "has an address": the guest agent needs about 35 s.
//   - Apple allows two macOS guests running at once per Mac (E039): Capacity is 2. Stopped
//     silos don't count. A third start is refused here, before Tart is asked, with ErrCapacity.
//   - A macOS silo is not isolated from its neighbours by default (they share Apple's NAT):
//     Softnet (see Options) puts each behind a packet filter. See network.go.
package tart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
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

// Name is the runtime's name in a Host's runtimes and a Silo's spec.runtime.
const Name = "tart"

// MaxRunning is how many macOS guests Apple lets one Mac run at once.
const MaxRunning = 2

// ErrCapacity: the Mac already runs MaxRunning macOS silos.
var ErrCapacity = errors.New("tart: this Mac already runs two macOS silos (Apple's limit); stop one first")

// capacityText is what Tart prints when Virtualization.framework refuses a third VM (E039).
const capacityText = "number of VMs exceeds the system limit"

// Runtime is the Tart runtime.
type Runtime struct {
	Host Runner
	// Detach starts a long-running command that outlives this call (and kevasod): `tart run`.
	// Default: a detached process of its own session, logging to StateDir/NAME.log.
	Detach func(c Cmd, logPath string) error
	// StateDir keeps what Kevaso remembers per silo (default /var/lib/kevaso/tart).
	StateDir string
	// RunAs is the Mac user tart runs as ("": kevasod's own user). kevasod runs as root on a Mac
	// (the mesh's utun needs it), but Tart's images and VMs are a user's, in that user's Tart
	// folder, and Virtualization.framework runs as a user: every tart command goes through
	// `sudo -u USER`.
	RunAs string
	// TartHome is the folder Tart keeps its images and VMs in ($TART_HOME; "": Tart's own default
	// in the home of the user kevasod runs as).
	TartHome string
	// Softnet puts every silo behind Tart's softnet packet filter (default-deny to the LAN and
	// other silos, internet allowed). It needs root; see Install.
	Softnet bool
	// ReadyWait is how long Start waits for the first exec to answer (default 5 minutes).
	ReadyWait time.Duration
	// PullWait is how long an image pull may take (default 12 hours: the base image is 27 GB).
	PullWait time.Duration
	// Sleep pauses between polls (tests: no-op).
	Sleep func(time.Duration)

	mu       sync.Mutex
	versions string
}

// state is what Kevaso remembers about a silo.
type state struct {
	ID      kri.ID `json:"id"`
	VM      string `json:"vm"` // the Tart VM name
	Image   string `json:"image"`
	CPU     int    `json:"cpu"`
	Memory  int64  `json:"memory"`
	Disk    int64  `json:"disk"`
	Running bool   `json:"running"` // Kevaso started it and hasn't stopped it
	Started bool   `json:"started"` // it has been started at least once (so a halt is Stopped, not Created)
}

// Info implements kri.Runtime.
func (r *Runtime) Info() kri.Info {
	return kri.Info{Name: Name, Version: r.versions, Capabilities: kri.Capabilities{
		Isolation: "vm", Network: "nic", UDP: true, InboundServices: true, Persistence: "disk", Exec: true,
		MaxSilos: MaxRunning,
	}}
}

// vmName is the Tart VM name of a silo: a name Tart takes as it is (letters, digits, "-" "_" ".")
// that carries the silo's UID, so a deleted and re-created silo is a different VM.
func vmName(id kri.ID) string {
	n := "kv-" + clean(id.Namespace) + "-" + clean(id.Name)
	if u := clean(id.UID); u != "" {
		if len(u) > 8 {
			u = u[:8]
		}
		n += "-" + u
	}
	return n
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

func clean(s string) string { return unsafeName.ReplaceAllString(s, "-") }

func (r *Runtime) dir() string {
	if r.StateDir != "" {
		return r.StateDir
	}
	return "/var/lib/kevaso/tart"
}

func (r *Runtime) statePath(id kri.ID) string { return filepath.Join(r.dir(), vmName(id)+".json") }
func (r *Runtime) logPath(vm string) string   { return filepath.Join(r.dir(), vm+".log") }

func (r *Runtime) load(id kri.ID) (state, bool) {
	b, err := r.Host.ReadFile(r.statePath(id))
	if err != nil {
		return state{}, false
	}
	var s state
	if json.Unmarshal(b, &s) != nil {
		return state{}, false
	}
	return s, true
}

func (r *Runtime) save(s state) error {
	b, _ := json.Marshal(s)
	return r.Host.WriteFile(r.statePath(s.ID), b, 0o600)
}

func (r *Runtime) sleep(d time.Duration) {
	if r.Sleep != nil {
		r.Sleep(d)
		return
	}
	time.Sleep(d)
}

// tart runs the tart program and returns its output; a non-zero exit is an error with it.
func (r *Runtime) tart(ctx context.Context, args ...string) (string, error) {
	var out bytes.Buffer
	code, err := r.Host.Run(ctx, r.cmd(args...).with(&out, &out, nil))
	if err != nil {
		return out.String(), err
	}
	if code != 0 {
		return out.String(), fmt.Errorf("tart %s: exit %d: %s", args[0], code, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func (r *Runtime) env() []string {
	if r.TartHome != "" {
		return []string{"TART_HOME=" + r.TartHome}
	}
	return nil
}

// tcmd is a tart command before its streams are set.
type tcmd struct{ Cmd }

func (c tcmd) with(stdout, stderr io.Writer, stdin io.Reader) Cmd {
	c.Stdout, c.Stderr, c.Stdin = stdout, stderr, stdin
	return c.Cmd
}

// cmd is `tart ARGS`, as RunAs when that is set: `sudo -n -H -u USER env VAR=… tart ARGS` started
// in "/", with the Homebrew folders on its PATH (sudo resets the environment).
func (r *Runtime) cmd(args ...string) tcmd {
	if r.RunAs == "" {
		return tcmd{Cmd{Name: "tart", Args: args, Env: r.env()}}
	}
	a := []string{"-n", "-H", "-u", r.RunAs, "env", "PATH=" + hostexec.DefaultPath()}
	a = append(a, r.env()...)
	a = append(a, "tart")
	// From "/": kevasod's own command folder is root's only, and Homebrew's tart is a bash script
	// that would warn into the output (and break `tart list --format json`) when it can't read it.
	return tcmd{Cmd{Name: "sudo", Args: append(a, args...), Dir: "/"}}
}

// vm is one entry of `tart list --format json`.
type vm struct {
	Name    string `json:"Name"`
	Source  string `json:"Source"` // local | OCI
	Running bool   `json:"Running"`
	State   string `json:"State"` // running | stopped | suspended
}

func (r *Runtime) list(ctx context.Context) ([]vm, error) {
	out, err := r.tart(ctx, "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var vms []vm
	if err := json.Unmarshal([]byte(out), &vms); err != nil {
		return nil, fmt.Errorf("tart list: not JSON: %w", err)
	}
	return vms, nil
}

func (v vm) running() bool { return v.Running || v.State == "running" }

func find(vms []vm, name string) (vm, bool) {
	for _, v := range vms {
		if v.Name == name {
			return v, true
		}
	}
	return vm{}, false
}

// Create clones the image into a VM of its own and sets its size. It doesn't start it.
func (r *Runtime) Create(ctx context.Context, spec kri.Spec) error {
	id := spec.ID
	name := vmName(id)
	if _, ok := r.load(id); ok {
		return nil
	}
	if spec.Image == "" {
		return errors.New("tart: the silo has no image (container.image: a macOS image reference)")
	}
	vms, err := r.list(ctx)
	if err != nil {
		return err
	}
	if _, ok := find(vms, name); !ok {
		if err := r.ensureImage(ctx, vms, spec.Image); err != nil {
			return err
		}
		if _, err := r.tart(ctx, "clone", spec.Image, name); err != nil {
			return err
		}
	}
	args := []string{"set", name}
	if spec.CPU > 0 {
		args = append(args, "--cpu", strconv.Itoa(spec.CPU))
	}
	if spec.Memory > 0 {
		args = append(args, "--memory", strconv.FormatInt((spec.Memory+(1<<20)-1)>>20, 10)) // MiB
	}
	if spec.DiskBytes > 0 {
		args = append(args, "--disk-size", strconv.FormatInt((spec.DiskBytes+(1<<30)-1)>>30, 10)) // GiB; only grows
	}
	if len(args) > 2 {
		if _, err := r.tart(ctx, args...); err != nil {
			return err
		}
	}
	return r.save(state{ID: id, VM: name, Image: spec.Image, CPU: spec.CPU, Memory: spec.Memory, Disk: spec.DiskBytes})
}

// ensureImage pulls image unless Tart already has it. A pull is slow (27 GB for the base image):
// it resumes after a cut connection, and a worker should have the image pulled ahead.
func (r *Runtime) ensureImage(ctx context.Context, vms []vm, image string) error {
	if _, ok := find(vms, image); ok {
		return nil
	}
	wait := r.PullWait
	if wait <= 0 {
		wait = 12 * time.Hour
	}
	pctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if _, err := r.tart(pctx, "pull", image); err != nil {
		return fmt.Errorf("tart: pull %s: %w (pull it ahead on this Mac with: tart pull %s)", image, err, image)
	}
	return nil
}

// running counts the macOS guests running now, other than skip.
func (r *Runtime) running(ctx context.Context, skip string) (int, error) {
	vms, err := r.list(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range vms {
		if v.running() && v.Name != skip {
			n++
		}
	}
	return n, nil
}

// startGrace is how long a VM may go unlisted as running right after `tart run` before Start
// calls it a failure.
const startGrace = 30 * time.Second

// Start boots the silo headless and returns once its first exec answers.
func (r *Runtime) Start(ctx context.Context, id kri.ID) error {
	s, ok := r.load(id)
	if !ok {
		return kri.ErrNotFound
	}
	vms, err := r.list(ctx)
	if err != nil {
		return err
	}
	me, present := find(vms, s.VM)
	if !present {
		return kri.ErrNotFound
	}
	if !me.running() {
		n, err := r.running(ctx, s.VM)
		if err != nil {
			return err
		}
		if n >= MaxRunning {
			return ErrCapacity
		}
		args := []string{"run", s.VM, "--no-graphics"}
		if r.Softnet {
			args = append(args, "--net-softnet")
		}
		detach := r.Detach
		if detach == nil {
			detach = detachLocal
		}
		if err := detach(r.cmd(args...).Cmd, r.logPath(s.VM)); err != nil {
			return fmt.Errorf("tart run: %w", err)
		}
	}
	s.Running, s.Started = true, true
	if err := r.save(s); err != nil {
		return err
	}
	return r.waitReady(ctx, s.VM)
}

// waitReady polls until a command runs in the guest.
func (r *Runtime) waitReady(ctx context.Context, name string) error {
	wait := r.ReadyWait
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	deadline := time.Now().Add(wait)
	var last error
	var notRunning time.Time // since when tart has not listed the VM as running
	for {
		if _, err := r.tart(ctx, "exec", name, "true"); err == nil {
			return nil
		} else {
			last = err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// Tart ran and gave up (the limit, a crash): the VM no longer runs.
		if vms, err := r.list(ctx); err == nil {
			if v, ok := find(vms, name); ok && !v.running() {
				if b, err := r.Host.ReadFile(r.logPath(name)); err == nil && strings.Contains(string(b), capacityText) {
					return ErrCapacity
				}
				// Tart lists the VM as running a moment after `tart run` starts it (seen on a
				// real Mac: the first poll came before): only a VM that stays down is a failure.
				if notRunning.IsZero() {
					notRunning = time.Now()
				}
				if time.Since(notRunning) > startGrace {
					return fmt.Errorf("tart: %s stopped while starting: %w (see %s)", name, last, r.logPath(name))
				}
			} else {
				notRunning = time.Time{}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("tart: %s isn't answering after %s: %w", name, wait, last)
		}
		r.sleep(2 * time.Second)
	}
}

// Stop shuts the guest down, keeping its disk.
func (r *Runtime) Stop(ctx context.Context, id kri.ID) error {
	return r.stop(ctx, id, "30")
}

// Kill stops it at once (a fence): no grace period.
func (r *Runtime) Kill(ctx context.Context, id kri.ID) error {
	return r.stop(ctx, id, "0")
}

func (r *Runtime) stop(ctx context.Context, id kri.ID, timeout string) error {
	s, ok := r.load(id)
	if !ok {
		return nil
	}
	vms, err := r.list(ctx)
	if err != nil {
		return err
	}
	if v, ok := find(vms, s.VM); ok && v.running() {
		if _, err := r.tart(ctx, "stop", s.VM, "--timeout", timeout); err != nil {
			return err
		}
	}
	s.Running = false
	return r.save(s)
}

// Delete removes the VM and what Kevaso remembers of it.
func (r *Runtime) Delete(ctx context.Context, id kri.ID) error {
	s, ok := r.load(id)
	if !ok {
		return nil
	}
	if err := r.Kill(ctx, id); err != nil {
		return err
	}
	vms, err := r.list(ctx)
	if err != nil {
		return err
	}
	if _, ok := find(vms, s.VM); ok {
		if _, err := r.tart(ctx, "delete", s.VM); err != nil {
			return err
		}
	}
	_ = r.Host.RemoveAll(r.logPath(s.VM))
	return r.Host.RemoveAll(r.statePath(id))
}

// Reset puts the silo back onto its image: a fresh clone, same ID.
func (r *Runtime) Reset(ctx context.Context, spec kri.Spec) error {
	s, ok := r.load(spec.ID)
	if ok {
		if err := r.Delete(ctx, spec.ID); err != nil {
			return err
		}
		if spec.Image == "" {
			spec.Image = s.Image
		}
		if spec.CPU == 0 {
			spec.CPU, spec.Memory, spec.DiskBytes = s.CPU, s.Memory, s.Disk
		}
	}
	return r.Create(ctx, spec)
}

// Status reports where the silo is.
func (r *Runtime) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	s, ok := r.load(id)
	if !ok {
		return kri.Status{State: kri.Absent}, nil
	}
	vms, err := r.list(ctx)
	if err != nil {
		return kri.Status{}, err
	}
	v, present := find(vms, s.VM)
	switch {
	case !present:
		return kri.Status{State: kri.Failed, Message: "the VM " + s.VM + " is gone from Tart"}, nil
	case v.running():
		// No Address: the VM's is on the Mac's own NAT (192.168.64.0/18 and the like), not the
		// cluster's silo subnet, and the control plane refuses it (ADR 0012: a macOS silo has no
		// cluster address yet). Reporting it kept the silo from ever being Running.
		return kri.Status{State: kri.Running}, nil
	case s.Running:
		return kri.Status{State: kri.Stopped, Message: "stopped by itself"}, nil
	case s.Started:
		return kri.Status{State: kri.Stopped}, nil
	default:
		return kri.Status{State: kri.Created}, nil
	}
}

// List returns every silo this runtime holds.
func (r *Runtime) List(context.Context) ([]kri.ID, error) {
	files, err := r.Host.Glob(filepath.Join(r.dir(), "kv-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []kri.ID
	for _, f := range files {
		b, err := r.Host.ReadFile(f)
		if err != nil {
			continue
		}
		var s state
		if json.Unmarshal(b, &s) == nil {
			out = append(out, s.ID)
		}
	}
	return out, nil
}

// Exec runs a command in the guest through the guest agent (`tart exec`): the exit code and stdin
// pass through, about a second a call once the guest is up (E038).
func (r *Runtime) Exec(ctx context.Context, id kri.ID, req kri.ExecRequest) (int, error) {
	s, ok := r.load(id)
	if !ok {
		return -1, kri.ErrNotFound
	}
	args := []string{"exec"}
	if req.Stdin != nil {
		args = append(args, "-i")
	}
	if req.TTY != nil {
		args = append(args, "-t")
	}
	// No "--": tart exec's usage is `tart exec [-i] [-t] NAME COMMAND…`, and a "--" is taken for the
	// command itself (exit 125, seen on a real Mac).
	args = append(args, s.VM)
	args = append(args, req.Command...)
	c := r.cmd(args...).with(req.Stdout, req.Stderr, req.Stdin)
	c.TTY = req.TTY
	return r.Host.Run(ctx, c)
}

// HasHostStorage: a silo's VM is its storage, held here until it is deleted.
func (r *Runtime) HasHostStorage(_ context.Context, id kri.ID) (bool, error) {
	_, ok := r.load(id)
	return ok, nil
}
