package fake

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/sdk/kri"
)

// Strict is the container fake (Box) made strict about what of a silo runs, as the container
// runtime is: an init step is a process of the silo that runs until it ends, is killed (Kill,
// Stop), or its caller goes away; Status says Running while any process of the silo runs, its
// main container or an init step; Kill and Stop end all of them. Several Strict runtimes, one per
// host, may share a World, which records every moment code of a silo runs on a host, so a test can
// say whether it ever ran on two hosts at once.
//
// The zero value isn't usable; use NewStrict.
type Strict struct {
	*Box
	// Host is this runtime's host, as the World knows it.
	Host  string
	World *World
	// HoldInit, if set, is asked as each init step begins: the step runs until the channel it
	// returns is closed (nil: it ends at once), exiting 0. A kill ends it first, exiting 137.
	HoldInit func(id kri.ID, step kri.InitStep) <-chan struct{}
	// OnRun, if set, is called just before code of a silo begins to run here: what is "init NAME"
	// or "main". It runs on the caller's goroutine (the agent's), before anything is recorded.
	OnRun func(what string, id kri.ID)

	smu        sync.Mutex
	inits      map[kri.ID]*heldInit
	refuseKill error
	failStatus error
	hangKill   <-chan struct{}
}

// FailStatus makes every Status from now on fail with err (nil: it answers again): an engine
// that can't say.
func (r *Strict) FailStatus(err error) {
	r.smu.Lock()
	defer r.smu.Unlock()
	r.failStatus = err
}

// HangKill makes every Kill from now on hang, whatever its context, until release is closed (nil:
// kills return again): a hung engine.
func (r *Strict) HangKill(release <-chan struct{}) {
	r.smu.Lock()
	defer r.smu.Unlock()
	r.hangKill = release
}

type heldInit struct {
	step   string
	killed chan struct{}
	once   sync.Once
}

func (h *heldInit) kill() { h.once.Do(func() { close(h.killed) }) }

// NewStrict returns an empty strict container fake for host (world may be nil).
func NewStrict(host string, world *World) *Strict {
	return &Strict{Box: NewBox(), Host: host, World: world, inits: map[kri.ID]*heldInit{}}
}

// Info implements kri.Runtime.
func (r *Strict) Info() kri.Info {
	i := r.Box.Info()
	i.Name = "fake-strict"
	return i
}

// RefuseKill makes every Kill and Stop from now on fail with err, leaving everything running (nil:
// they work again).
func (r *Strict) RefuseKill(err error) {
	r.smu.Lock()
	defer r.smu.Unlock()
	r.refuseKill = err
}

func (r *Strict) refused() error {
	r.smu.Lock()
	defer r.smu.Unlock()
	return r.refuseKill
}

// InitRunning reports whether an init step of the silo runs now (and which).
func (r *Strict) InitRunning(_ context.Context, id kri.ID) (bool, error) {
	r.smu.Lock()
	defer r.smu.Unlock()
	_, ok := r.inits[id]
	return ok, nil
}

// RunningInit is the init step of the silo that runs now ("" if none).
func (r *Strict) RunningInit(id kri.ID) string {
	r.smu.Lock()
	defer r.smu.Unlock()
	if h := r.inits[id]; h != nil {
		return h.step
	}
	return ""
}

// RunInit implements kri.InitContainers: the step runs (HoldInit) until it ends, is killed, or ctx
// ends; it finds the secret files on the host as Box records them.
func (r *Strict) RunInit(ctx context.Context, id kri.ID, step kri.InitStep, out io.Writer) (int, error) {
	if r.OnRun != nil {
		r.OnRun("init "+step.Name, id)
	}
	r.mu.Lock()
	_, err := r.get(id)
	r.mu.Unlock()
	if err != nil {
		return -1, err
	}
	h := &heldInit{step: step.Name, killed: make(chan struct{})}
	r.smu.Lock()
	if _, busy := r.inits[id]; busy {
		r.smu.Unlock()
		return -1, fmt.Errorf("%s: an init step runs already", id)
	}
	r.inits[id] = h
	r.smu.Unlock()
	r.World.begin(r.Host, id, "init "+step.Name)
	defer func() {
		r.smu.Lock()
		if r.inits[id] == h {
			delete(r.inits, id)
		}
		r.smu.Unlock()
		r.World.end(r.Host, id, "init "+step.Name)
	}()
	if _, err := r.Box.RunInit(ctx, id, step, out); err != nil {
		return -1, err
	}
	var hold <-chan struct{}
	if r.HoldInit != nil {
		hold = r.HoldInit(id, step)
	}
	if hold == nil {
		return 0, nil
	}
	select {
	case <-hold:
		return 0, nil
	case <-h.killed:
		return 137, nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// Start implements kri.Runtime: the main process runs.
func (r *Strict) Start(ctx context.Context, id kri.ID) error {
	if r.OnRun != nil {
		r.OnRun("main", id)
	}
	if err := r.Box.Start(ctx, id); err != nil {
		return err
	}
	r.World.begin(r.Host, id, "main")
	return nil
}

// endAll ends every process of the silo here: its init step and its main process.
func (r *Strict) endAll(id kri.ID) {
	r.smu.Lock()
	h := r.inits[id]
	r.smu.Unlock()
	if h != nil {
		h.kill()
	}
	r.World.end(r.Host, id, "main")
}

// Stop implements kri.Runtime: everything of the silo stops (refused while RefuseKill is set).
func (r *Strict) Stop(ctx context.Context, id kri.ID) error {
	if err := r.refused(); err != nil {
		r.mu.Lock()
		r.record("stop (refused)", id)
		r.mu.Unlock()
		return err
	}
	err := r.Box.Stop(ctx, id)
	r.endAll(id)
	return err
}

// Kill implements kri.Killer: everything of the silo ends at once (refused while RefuseKill is
// set).
func (r *Strict) Kill(ctx context.Context, id kri.ID) error {
	r.smu.Lock()
	hang := r.hangKill
	r.smu.Unlock()
	if hang != nil {
		<-hang
	}
	if err := r.refused(); err != nil {
		r.mu.Lock()
		r.record("kill (refused)", id)
		r.mu.Unlock()
		return err
	}
	err := r.Box.Kill(ctx, id)
	r.endAll(id)
	return err
}

// Delete implements kri.Runtime.
func (r *Strict) Delete(ctx context.Context, id kri.ID) error {
	r.endAll(id)
	return r.Box.Delete(ctx, id)
}

// Reset implements kri.Resetter.
func (r *Strict) Reset(ctx context.Context, spec kri.Spec) error {
	r.endAll(spec.ID)
	return r.Box.Reset(ctx, spec)
}

// Status implements kri.Runtime: Running while its main process or an init step runs.
func (r *Strict) Status(ctx context.Context, id kri.ID) (kri.Status, error) {
	r.smu.Lock()
	ferr := r.failStatus
	r.smu.Unlock()
	if ferr != nil {
		return kri.Status{}, ferr
	}
	st, err := r.Box.Status(ctx, id)
	if err != nil || st.State == kri.Running {
		return st, err
	}
	if step := r.RunningInit(id); step != "" {
		return kri.Status{State: kri.Running, Message: "init step " + step + " running"}, nil
	}
	return st, nil
}

// World is what runs where, across the Strict runtimes of several hosts: for each silo (by UID),
// the hosts where code of it runs now, and every moment it ran on two or more at once.
type World struct {
	mu      sync.Mutex
	running map[string]map[string]map[string]bool // uid → host → what → running
	twice   []string
}

// NewWorld returns an empty world.
func NewWorld() *World { return &World{running: map[string]map[string]map[string]bool{}} }

func (w *World) begin(host string, id kri.ID, what string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	hosts := w.running[id.UID]
	if hosts == nil {
		hosts = map[string]map[string]bool{}
		w.running[id.UID] = hosts
	}
	if hosts[host] == nil {
		hosts[host] = map[string]bool{}
	}
	hosts[host][what] = true
	if len(hosts) > 1 {
		w.twice = append(w.twice, fmt.Sprintf("%s (%s) runs on %s at once (%s began on %s)", id, id.UID, strings.Join(w.hostsLocked(id.UID), " and "), what, host))
	}
}

func (w *World) end(host string, id kri.ID, what string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	hosts := w.running[id.UID]
	if hosts == nil || hosts[host] == nil {
		return
	}
	delete(hosts[host], what)
	if len(hosts[host]) == 0 {
		delete(hosts, host)
	}
}

func (w *World) hostsLocked(uid string) []string {
	var out []string
	for h := range w.running[uid] {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Hosts are the hosts where code of the silo runs now.
func (w *World) Hosts(uid string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hostsLocked(uid)
}

// RunsOn reports whether code of the silo runs on host now.
func (w *World) RunsOn(uid, host string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.running[uid][host]) > 0
}

// Twice is every moment a silo ran on two or more hosts at once (empty: never).
func (w *World) Twice() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.twice...)
}

// ErrKillRefused is a kill a test made fail (RefuseKill(ErrKillRefused)): an engine that hangs or
// refuses.
var ErrKillRefused = errors.New("the engine refused the kill")

var (
	_ kri.InitContainers = (*Strict)(nil)
	_ kri.HostSecrets    = (*Strict)(nil)
	_ kri.Killer         = (*Strict)(nil)
	_ kri.Resetter       = (*Strict)(nil)
)

// CallLog is every operation so far, in order (Calls, read safely while the runtime is in use).
func (r *Runtime) CallLog() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.Calls...)
}
