// Package fence stops, on a host whose agent has lost the control plane (cut off, or not running
// at all), the silos that asked for it: onControlPlaneLoss: Stop, each after its own `after`
// (brainstorm §0.7, record version 2). Nothing else is stopped: a worker that loses the control
// plane keeps running what it was given. Records from agents before version 2 keep the old rule
// described below until those agents are upgraded.
//
// The agent writes a record every second: when it last reached the control plane, and the
// onHostLoss policy of each silo it runs here. A small watcher, its own process and unit
// (kevasod fence-watch), reads it: when the last contact is older than FenceAfter, it stops this
// host's Recreate and Move silos through the runtimes, as the agent's own fence does. A dead agent
// and a cut-off agent look the same from outside: neither renews the contact.
//
// Timing, from the last contact the record holds (the agent may die right after it): every silo is
// stopped by FenceAfter + CheckEvery + KillWithin (36s), killed rather than stopped gracefully; the
// control plane, judging by the same heartbeat, calls the host lost after its lease (40s) and
// starts another copy RecreateAfter (30s) later, minus what second-resolution timestamps and clock
// skew can take off (MaxSkew): 67s at the earliest. agent.TestFenceTiming holds the margin to
// MinMargin. An agent restart shorter than FenceAfter (minus the heartbeat period) stops nothing.
package fence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/sdk/kri"
)

// Dir is where the record lives: tmpfs, so a reboot forgets it (nothing runs after one anyway),
// and not kevasod's own runtime directory (/run/kevaso), which systemd removes when kevasod stops.
var Dir = defaultDir()

// defaultDir: /run is tmpfs on Linux; a Mac has no /run, and /var/run is cleared at boot.
func defaultDir() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/kevaso-fence"
	}
	return "/run/kevaso-fence"
}

// DefaultAfter is how old the last contact may get before a fence: under the control plane's host
// lease (40s), so the old copy is stopped before the host is even called lost.
const DefaultAfter = 30 * time.Second

// The fence's side of the timing (see the package doc).
const (
	// CheckEvery is how often the watcher reads the record (and the agent checks its contact).
	CheckEvery = time.Second
	// KillWithin is how long a fence may take to kill every silo it stops: they're killed at
	// once (kri.Kill), all together; a kill that takes longer is logged and tried again.
	KillWithin = 5 * time.Second
	// MaxSkew is what may make the control plane see the last heartbeat earlier than the host
	// did: heartbeat and condition times truncated to the second (1s each), and clock skew
	// between the host and the control plane (up to 2s, NTP assumed).
	MaxSkew = 4 * time.Second
	// MinMargin is the least time between "every silo stopped" and "another copy started
	// elsewhere" the timings must leave.
	MinMargin = 15 * time.Second
)

// WorstStopped is, from the last contact, when every movable silo is stopped at the latest.
func WorstStopped(after time.Duration) time.Duration { return after + CheckEvery + KillWithin }

// RecordFile is the record's name in Dir.
const RecordFile = "record.json"

// RecordVersion is the record's current version. Version 2 (brainstorm §0.7): the fence stops
// only the silos that asked for it, each after its own StopAfter (spec.availability.after, for
// onControlPlaneLoss: Stop); onHostLoss and Fence mean nothing to it. A record without a version
// is an agent from before: the old rule (Recreate and Move silos after FenceAfter, where Fence)
// until that agent is upgraded.
//
// Timing (version 2), what the control plane counts on: LastContact is the time the agent SENT
// the last heartbeat (its own Host status write) that succeeded, never a later answer, and never
// a time it got from elsewhere. The control plane sees that write after it was sent, so its own
// "last heard of this host" is never earlier than the agent's LastContact; each side then counts
// a duration on its own clock. The control plane starts another copy only StopMargin after
// StopAfter (internal/controllers/silo).
const RecordVersion = 2

// Record is what the agent writes.
type Record struct {
	Version int `json:"version,omitempty"` // RecordVersion; 0: an agent from before it
	// LastContact is when the agent last reached the control plane (what the agent's own fence
	// judges by). Zero: never yet, so nothing here may run elsewhere.
	LastContact time.Time `json:"lastContact"`
	Written     time.Time `json:"written"` // when the agent wrote this (it's alive)
	// BootID and ContactBoot (version 2, K-072): the last contact on the boot clock
	// (internal/boottime), which no time server steps. A watcher of the same boot counts the
	// silence on it; LastContact (wall) only across boots.
	BootID      string        `json:"bootID,omitempty"`
	ContactBoot time.Duration `json:"contactBoot,omitempty"`
	// Fence: a second copy of this host's silos could be started elsewhere while this one may
	// still run (see Applies). False: the watcher stops nothing, ever.
	Fence bool   `json:"fence"`
	Silos []Silo `json:"silos"`
}

// Silo is one silo the agent runs here.
type Silo struct {
	ID         kri.ID `json:"id"`
	Runtime    string `json:"runtime"`
	OnHostLoss string `json:"onHostLoss"` // Wait | Recreate | Move (version 1 only)
	// StopAfter (version 2): the silo's onControlPlaneLoss is Stop, and this is its after
	// ((*v1.Silo).StopsOnControlPlaneLoss): stopped once the last contact is older. 0: never.
	StopAfter time.Duration `json:"stopAfter,omitempty"`
}

// Stops reports whether a silo with this policy is stopped by a fence: only those the control
// plane may start elsewhere. Wait silos stay put. A silo with no policy recorded isn't stopped
// either (stopping what may be a Wait silo is its own harm); the agent records a silo before it
// starts it and keeps it until its runtime no longer has it, so a running silo without a record is
// a fault, which the watcher logs and the agent reports once in contact (Faults).
func Stops(policy string) bool {
	return policy == v1.OnHostLossRecreate || policy == v1.OnHostLossMove
}

// Applies reports whether a host needs fencing: whether, with this host cut off or its agent down,
// the rest of the cluster could start a second copy of its silos. Pure.
//
//   - No worker: nothing runs here.
//   - A worker only: the control plane is elsewhere and carries on without it. Always.
//   - Control plane and worker: only when the control plane carries on without this host: another
//     system node serves the API and the store members without this one are a majority. A
//     one-node cluster (or two system nodes: neither is a majority alone) has nobody to start
//     the silos elsewhere, and a fence there would only stop silos for nothing.
//
// self missing from hosts (not registered yet) counts as a worker only: fencing is the safe side.
func Applies(hosts []v1.Host, self string) bool {
	var me *v1.Host
	members, others, apiOthers := 0, 0, 0
	for i := range hosts {
		h := &hosts[i]
		if h.Name == self {
			me = h
		}
		cp := h.Spec.Components.ControlPlane
		if cp == nil {
			continue
		}
		members++
		if h.Name != self {
			others++
			if !cp.StateOnly {
				apiOthers++
			}
		}
	}
	switch {
	case me == nil:
		return true
	case me.Spec.Components.Worker == nil:
		return false
	case me.Spec.Components.ControlPlane == nil:
		return true
	}
	return apiOthers > 0 && 2*others > members
}

// Decide is what to stop now, minus those already stopped in this fence. Pure.
//
// Version 2: each silo with a StopAfter, once the last contact is older than it; nothing else,
// whatever Fence says (a silo that asked to stop on control-plane loss stops on a one-node cluster
// too). Version 1: the silos the control plane used to start elsewhere (Stops), once the last
// contact is older than after, where Fence.
func Decide(r Record, now time.Time, after time.Duration, done map[string]bool) []Silo {
	if r.LastContact.IsZero() {
		return nil
	}
	silent := now.Sub(r.LastContact)
	var out []Silo
	for _, s := range r.Silos {
		if done[s.ID.UID] {
			continue
		}
		if r.Version >= RecordVersion {
			if s.StopAfter > 0 && silent > s.StopAfter {
				out = append(out, s)
			}
		} else if r.Fence && silent > after && Stops(s.OnHostLoss) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.UID < out[j].ID.UID })
	return out
}

// Write saves the record atomically (a reader never sees half of it).
func Write(dir string, r Record) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+RecordFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, RecordFile))
}

// Read loads the record; a missing one is the zero Record (nothing to fence).
func Read(dir string) (Record, error) {
	var r Record
	b, err := os.ReadFile(filepath.Join(dir, RecordFile))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

// StampFile is the watcher's stamp, written on every check (K-067): which record version it
// reads, and when, on the boot clock. The agent arms a silo's fence (ArmedCondition) only while
// the stamp is fresh: "armed" means a watcher of this version is running, not that a file was
// written.
const StampFile = "watcher.json"

// StampFresh is how old a stamp may be and still say its watcher runs.
const StampFresh = 5 * time.Second

// Stamp is the watcher's stamp.
type Stamp struct {
	Version int           `json:"version"` // the record version it reads
	BootID  string        `json:"bootID"`
	Boot    time.Duration `json:"boot"` // the boot clock at the check
	At      time.Time     `json:"at"`   // the same, for people
}

// WriteStamp writes the stamp atomically.
func WriteStamp(dir string, st Stamp) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+StampFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, StampFile))
}

// ReadStamp reads the stamp; false when there is none.
func ReadStamp(dir string) (Stamp, bool, error) {
	var st Stamp
	b, err := os.ReadFile(filepath.Join(dir, StampFile))
	if errors.Is(err, os.ErrNotExist) {
		return st, false, nil
	}
	if err != nil {
		return st, false, err
	}
	return st, true, json.Unmarshal(b, &st)
}

// Live reports whether a stamp says a watcher of this boot, reading this record version or a
// later one, checked within StampFresh. Pure.
func Live(st Stamp, bootID string, bootNow time.Duration) bool {
	return st.Version >= RecordVersion && st.BootID == bootID && bootNow-st.Boot <= StampFresh && bootNow >= st.Boot
}

// FaultsFile is the watcher's report of its last fence, for the agent to pick up.
const FaultsFile = "faults.json"

// ConditionFaults is the Host condition the agent reports a fence's faults with.
const ConditionFaults = "FenceFaults"

// Faults is what the watcher found during a fence: running silos it has no record of (and so left
// running). Empty Silos: a clean fence.
type Faults struct {
	At    time.Time `json:"at"`
	Silos []Silo    `json:"silos"` // OnHostLoss empty: not recorded
}

// WriteFaults saves the report atomically.
func WriteFaults(dir string, f Faults) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+FaultsFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FaultsFile))
}

// ReadFaults loads the report; ok false when there's none.
func ReadFaults(dir string) (f Faults, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(dir, FaultsFile))
	if errors.Is(err, os.ErrNotExist) {
		return f, false, nil
	}
	if err != nil {
		return f, false, err
	}
	return f, true, json.Unmarshal(b, &f)
}

// RemoveFaults removes the report once reported.
func RemoveFaults(dir string) error {
	err := os.Remove(filepath.Join(dir, FaultsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Unrecorded is, of the silos the runtimes have running, those the record doesn't name. Pure.
func Unrecorded(r Record, running []Silo) []Silo {
	known := map[string]bool{}
	for _, s := range r.Silos {
		known[s.ID.UID] = true
	}
	var out []Silo
	for _, s := range running {
		if !known[s.ID.UID] {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.UID < out[j].ID.UID })
	return out
}

// Watcher stops silos when the record says the agent lost its contact.
type Watcher struct {
	Dir        string
	Runtimes   map[string]kri.Runtime
	FenceAfter time.Duration
	Every      time.Duration // how often the record is read (default CheckEvery)
	Now        func() time.Time
	// Boot, if set, is this boot's id and the boot clock now (default internal/boottime).
	Boot func() (id string, now time.Duration)
	Log  func(string, ...any)

	done      map[string]bool // stopped in this fence (confirmed), by silo UID
	noRuntime map[string]bool // logged: must stop, no runtime here
	fencing   bool
	faults    Faults // this fence's
}

func (w *Watcher) boot() (string, time.Duration) {
	if w.Boot != nil {
		return w.Boot()
	}
	return boottime.ID(), boottime.Now()
}

// Check reads the record once and stops what must be stopped.
func (w *Watcher) Check(ctx context.Context) {
	if w.done == nil {
		w.done = map[string]bool{}
	}
	if w.noRuntime == nil {
		w.noRuntime = map[string]bool{}
	}
	r, err := Read(w.Dir)
	if err != nil {
		w.log("fence: reading the record: %v", err)
		return
	}
	now := w.now()
	id, bnow := w.boot()
	if err := WriteStamp(w.Dir, Stamp{Version: RecordVersion, BootID: id, Boot: bnow, At: now.UTC()}); err != nil {
		w.log("fence: the stamp: %v", err)
	}
	if r.BootID != "" && r.BootID == id && r.ContactBoot > 0 && !r.LastContact.IsZero() {
		// K-072: the silence on the boot clock, as Decide reads it (last contact + silence).
		now = r.LastContact.Add(bnow - r.ContactBoot)
	}
	stop := Decide(r, now, w.FenceAfter, w.done)
	cut := !r.LastContact.IsZero() && now.Sub(r.LastContact) > w.FenceAfter
	if r.Version >= RecordVersion {
		cut = len(stop) > 0 || (w.fencing && !r.LastContact.IsZero() && now.Sub(r.LastContact) > w.FenceAfter)
	}
	switch {
	case cut && r.Version >= RecordVersion && !w.fencing:
		w.fencing = true
		w.faults = Faults{At: now}
		w.log("fence: no contact with the control plane recorded for %s: stopping the silos that asked to stop (onControlPlaneLoss: Stop)",
			now.Sub(r.LastContact).Round(time.Second))
		w.writeFaults()
	case cut && r.Fence && !w.fencing:
		w.fencing = true
		w.faults = Faults{At: now}
		w.log("fence: no contact with the control plane recorded for %s (over %s): stopping silos with onHostLoss Recreate or Move",
			now.Sub(r.LastContact).Round(time.Second), w.FenceAfter)
		w.writeFaults()
	case !cut && w.fencing:
		w.fencing, w.done, w.noRuntime = false, map[string]bool{}, map[string]bool{}
		w.log("fence: contact is back: the agent takes over again")
	}
	// All at once, each killed (no graceful stop): KillWithin bounds the whole fence.
	kctx, cancel := context.WithTimeout(ctx, KillWithin)
	defer cancel()
	errs := make([]error, len(stop))
	var wg sync.WaitGroup
	for i, s := range stop {
		rt, ok := w.Runtimes[s.Runtime]
		if !ok {
			errs[i] = errNoRuntime
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = kri.Kill(kctx, rt, s.ID) }()
	}
	wg.Wait()
	for i, s := range stop {
		switch err := errs[i]; {
		case errors.Is(err, errNoRuntime):
			// Never counted done (K-067): it may run. Logged once a fence; the agent reports it.
			if !w.noRuntime[s.ID.UID] {
				w.noRuntime[s.ID.UID] = true
				w.log("FENCE FAULT: %s/%s must stop and this watcher has no runtime %s: trying on every check", s.ID.Namespace, s.ID.Name, s.Runtime)
			}
		case err == nil && w.stillRunning(ctx, s):
			w.log("fence: killing %s/%s: it still runs (trying again)", s.ID.Namespace, s.ID.Name)
		case err == nil || errors.Is(err, kri.ErrNotFound):
			w.done[s.ID.UID] = true
			if s.StopAfter > 0 {
				w.log("fence: stopped %s/%s (onControlPlaneLoss: Stop, after %s)", s.ID.Namespace, s.ID.Name, s.StopAfter)
			} else {
				w.log("fence: stopped %s/%s (onHostLoss %s)", s.ID.Namespace, s.ID.Name, s.OnHostLoss)
			}
		default:
			w.log("fence: killing %s/%s: %v (trying again)", s.ID.Namespace, s.ID.Name, err)
		}
	}
	if w.fencing {
		w.findUnrecorded(ctx, r)
	}
}

// stillRunning: a kill reported done is confirmed by the runtime (K-067).
func (w *Watcher) stillRunning(ctx context.Context, s Silo) bool {
	st, err := w.Runtimes[s.Runtime].Status(ctx, s.ID)
	return err == nil && st.State == kri.Running
}

// findUnrecorded looks, during a fence, for running silos the record doesn't name: a fault (the
// agent records every silo before starting it). Each is logged loudly once and reported.
func (w *Watcher) findUnrecorded(ctx context.Context, r Record) {
	var running []Silo
	for name, rt := range w.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			w.log("fence: listing %s: %v", name, err)
			continue
		}
		for _, id := range ids {
			if st, err := rt.Status(ctx, id); err == nil && st.State == kri.Running {
				running = append(running, Silo{ID: id, Runtime: name})
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range w.faults.Silos {
		seen[s.ID.UID] = true
	}
	added := false
	for _, s := range Unrecorded(r, running) {
		if seen[s.ID.UID] {
			continue
		}
		w.log("fence: FAULT: %s/%s (uid %s, %s) is running with no recorded policy: left running, it may also be started elsewhere",
			s.ID.Namespace, s.ID.Name, s.ID.UID, s.Runtime)
		w.faults.Silos = append(w.faults.Silos, s)
		added = true
	}
	if added {
		w.writeFaults()
	}
}

func (w *Watcher) writeFaults() {
	if err := WriteFaults(w.Dir, w.faults); err != nil {
		w.log("fence: writing the faults report: %v", err)
	}
}

var errNoRuntime = errors.New("no such runtime here")

// Run checks every period until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = CheckEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		w.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Watcher) log(format string, args ...any) {
	if w.Log != nil {
		w.Log(format, args...)
	}
}

// Unit is the watcher's systemd unit: its own, restarted on its own, and not tied to kevasod's
// (stopping or killing kevasod must leave it running: that's when it's needed). Every host with a
// worker gets it, a control plane's included: whether it ever stops anything is the record's Fence,
// which the agent keeps current as system nodes come and go.
func Unit(runtimes []string, after time.Duration) string {
	args := "fence-watch --fence-after " + after.String()
	for _, r := range runtimes {
		args += " --runtime " + r
	}
	return fmt.Sprintf(`[Unit]
Description=Kevaso fence: stops the silos that ask to stop when this host's agent loses the control plane
After=network-online.target docker.service

[Service]
ExecStart=/usr/local/bin/kevasod %s
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`, args)
}
