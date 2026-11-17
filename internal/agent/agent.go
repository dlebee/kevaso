// Package agent is the worker component of kevasod: it runs the silos placed on its host.
//
// For each silo whose status.host is this host it drives the silo's runtime towards running,
// then runs its init steps (in order, through the runtime's Exec) before marking it Ready. A silo
// that's gone from the API but still present in a runtime is deleted there. Everything is
// level-triggered and idempotent: the agent can restart at any point and pick up where it was.
package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/boottime"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/internal/policy"
	"kevaso.com/core/internal/probes"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/sdk/kri"
)

// Phases the agent sets.
const (
	PhaseStarting = "Starting" // created, booting, or running init steps
	PhaseRunning  = "Running"  // running, init done: Ready
	PhaseFailed   = "Failed"   // the runtime couldn't create or start it
)

// Agent runs this host's silos.
type Agent struct {
	Client   *client.Client
	HostName string
	Runtimes map[string]kri.Runtime // by name, e.g. "cloud-hypervisor"
	// RuntimeReady says whether a runtime has finished installing (nil: all are). Until it has, its
	// silos are neither made nor started: a microVM started before its runtime's storage is up
	// fails, and a failed one stays failed.
	RuntimeReady func(name string) bool
	// Bound is the worker's loaded bridge bindings (address → port), for the local endpoint
	// (K-002): nil until the worker gives it.
	Bound func(netip.Addr) (port string, ok bool)
	Clock clock.Clock
	Log   func(format string, args ...any)
	// LastContact, if set, says when this host last reached the control plane. Without contact the
	// agent changes nothing (§0.7), except for the silos that asked for it: each silo with
	// onControlPlaneLoss: Stop is stopped once the contact is older than its after, and not
	// started again until the contact is back.
	LastContact func() time.Time
	// LastContactBoot, if set, is the same contact on the boot clock (internal/boottime): the
	// silence is counted on it, never on the wall clock (K-072).
	LastContactBoot func() (time.Duration, bool)
	// HostIsVM, if set, says whether this host is itself a virtual machine (K-093); nil: asked of
	// the host once (DetectVM). A VM paused by its hypervisor may not advance its boot clock, so on
	// one the silence is counted on either clock, whichever says more.
	HostIsVM func() bool
	isVMOnce sync.Once
	isVM     bool
	// StopsOnLoss, if set, replaces (*v1.Silo).StopsOnControlPlaneLoss (tests shorten the times).
	StopsOnLoss func(*v1.Silo) (stops bool, after time.Duration)
	// WatermarkFile, if set, is where the agent keeps what it saw of its control plane (cluster,
	// history, highest revision; watermark.go), across restarts and reboots. Answers are judged
	// only where the client's ControlPlane is ControlPlaneJudge (set by whoever makes the client,
	// before it is used).
	WatermarkFile string
	// Watermark, if set, is the one kevasod made (OpenWatermark), shared with the client and the
	// worker's network; WatermarkFile is then not read.
	Watermark *Watermark
	// FenceDir, if set, is where the agent writes its fence record every second (internal/fence):
	// its last contact and which of its silos stop on control-plane loss, for the fence watcher,
	// which stops those when this agent can no longer vouch for them, running or not.
	FenceDir string
	// DeletesFile, if set, is where the agent keeps the silo deletes it saw whose copies here may
	// not all be gone (deletes.go); by default SeenDeletesFile beside the watermark's file.
	DeletesFile string
	// FenceApplies is no longer read: per §0.7 the fence acts where a silo asked for it (Stop),
	// whoever else could start its silos. Left for the worker's wiring until that goes.
	FenceApplies func() (applies, known bool)
	// EgressCA is the host's egress CA: the agent puts it in the trust store of the VM silos whose
	// grants inject (containers get the runtime's read-only bundle).
	EgressCA []byte
	// EndpointListen, if set, is where the agent serves its silos' local endpoint (ADR 0009:
	// 169.254.42.1:80 on the silo bridge).
	EndpointListen string
	// Host runs commands on the host, for provider volumes (format once, mount); nil: this host
	// can't mount them. VolumesDir is where they go (default DefaultVolumesDir).
	Host       hostexec.Runner
	VolumesDir string
	// Nodes are the plugins' node sides on this host (NAME/node.sock), which mount the volumes of
	// mount-reach storage classes (juicefs) and hold their credentials; nil: none.
	Nodes *plugins.Registry
	// PluginsEtc is where kvoadm records cluster-secret names for plugins installed here
	// (DIR/PLUGIN/cluster-secrets.json, and cluster-secrets-node.json for a node side).
	// Empty: this agent delivers none.
	PluginsEtc string
	// RestartUnit restarts a plugin unit after its cluster secret was written or removed.
	// Nil: systemctl restart, with a fixed environment and only the unit name on the command
	// line. Tests set it.
	RestartUnit func(ctx context.Context, unit string) error
	// ClusterSecretEvery is how often a failed cluster-secret fetch is tried again (default 5s).
	ClusterSecretEvery time.Duration
	// Probe looks at a mount-reach volume's folder; it's not answering while it hasn't returned
	// (default: a lookup in it). Tests replace it.
	Probe func(dir string) error
	// ProbeTimeout is how long it may take (default DefaultProbeTimeout); ProbeEvery how often a
	// running silo with such volumes is looked at (default DefaultProbeEvery).
	ProbeTimeout, ProbeEvery time.Duration
	// TunnelRefresh is how often the agent looks for system nodes to hold a tunnel to (tunnels.go).
	TunnelRefresh time.Duration
	// ProbeDial, if set, dials tcp and http probes instead of the host's own dialer (tests).
	ProbeDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// IngressEvery is how often it looks at its ingress controller silos again (ingress.go).
	IngressEvery time.Duration
	// Resync, if set, replaces ResyncEvery for this agent (tests: never the global, which other
	// tests' agents still read).
	Resync time.Duration
	// ClaimRefresh, if set, replaces ClaimRefreshEvery (tests).
	ClaimRefresh time.Duration
	// ShutdownWait, if set, replaces ShutdownWait (tests).
	ShutdownWait time.Duration
	// OnEndpoints, if set, hears the control planes the agent's client may use whenever it learns
	// more from the system nodes (the worker keeps them for its next start).
	OnEndpoints func([]string)

	tunnelsSeen []string // the last tunnel targets found (only RunTunnels touches it)
	silos       *informer.Informer
	secrets     *informer.Informer
	grants      *informer.Informer
	fenced      atomic.Bool
	silosSynced atomic.Bool
	fencePrev   fence.Record  // the fence record as an earlier run left it (FenceDir)
	started     time.Time     // when this run began (Run)
	startedBoot time.Duration // the same, on the boot clock
	fenceMu     sync.Mutex    // the record: built and written by one at a time
	recorded    map[string]fence.Silo
	goneChecked time.Time
	endpoint    *Endpoint
	delivered   sync.Map // silo uid → delivered: its file and env secrets as this agent last wrote them
	leftovers   sync.Map // silo uid → struct{}: looked at for what an earlier run delivered (deliveries.go)
	paneRuns    sync.Map // silo uid → paneRun: its pane fetcher
	panesMu     sync.Mutex
	runCtx      context.Context
	kept        sync.Map // silo uid → keptState: its daemons and upkeep as this agent last decided
	probed      sync.Map // silo uid → probeState: its probes as this agent last decided
	// nodeMounts: volume path → handle, mounted here by a node side during this agent's run.
	nodeMounts sync.Map
	// probes: a mount-reach volume's folder → its probe going (probe.go); probeSaid: → what the
	// last finished one found.
	probes, probeSaid sync.Map
	// guestMounted: silo uid → the volumes its guest last mounted (runtimes with kri.GuestVolumes).
	guestMounted sync.Map
	// heldBack: silo uid → struct{}: an old copy kept here, stopped, for its host-local volumes
	// (removeEverywhere).
	heldBack sync.Map
	// seenDeleted: silo uid → struct{}: a delete of that silo this agent saw on its own watch.
	// Only such a delete removes a silo's disk and volumes (design §0.7): a silo that is merely
	// missing from the API (a control plane restored from an older backup, a re-made cluster) is
	// kept, running, with its data, and listed (kept, logged once).
	seenDeleted sync.Map // silo uid → the history (Watermark.history) its delete was seen under
	// seenIDs: silo uid → kri.ID, the seen deletes of silos this host may hold (mayHaveHere): a
	// copy its runtime doesn't list is looked for by name (stopUnlisted).
	seenIDs sync.Map
	// placedUnder: silo uid → the history (Watermark.history) under which this host last read it
	// placed here in the store (writeStatus), kept on disk for the next run (placed.go, K-126).
	// historyAtStart: the one trusted when this run began. A handoff read under another history is
	// a restored store's replay, not an order (K-112). placedOther: the disk record has a placement
	// from another history, or can't be read; a copy with no entry is that replay too.
	placedUnder    sync.Map
	historyAtStart string
	placed         placedLog
	placedOther    bool
	// abandoned: silo uid → struct{}: a start ended because the store didn't know the silo, whose
	// stop failed: tried again until it stops (stopAbandoned).
	abandoned     sync.Map
	inFlight      sync.Map   // engine.Key → time.Time: a reconcile under way since then (awaitReconciles)
	interrupts    sync.Map   // engine.Key → *interruptible: the work under way inside that silo (whileItRuns)
	deletes       deletesLog // the deletes seen whose copies may remain here, on disk (deletes.go)
	keptNoted     sync.Map   // silo UID → keptCopy: kept, listed on the Host (ConditionKeptSilos)
	engine        *engine.Engine
	cp            *Watermark // the control plane this worker trusts (watermark.go); via watermark()
	cpOnce        sync.Once
	staleNoted    sync.Map // silo UID → logged once that its cache was stale at a start
	claims        sync.Map // silo UID → *claimKeeper: its start claim, kept fresh while it starts here
	reported      sync.Map // silo UID → generation: reported Running in this run since its last start here
	createBackoff sync.Map // silo UID → createBackoff
	startBackoff  sync.Map // silo UID → createBackoff: its failed starts (K-115)
	// startedHere: silo UID → struct{}: this run started it, and hasn't stopped it since
	// (stoppedByUs). Found stopped while it is there, it stopped by itself: a failed start (K-115).
	startedHere sync.Map
	// fenceFaulted: silo UID → why: its fence kill here failed, or wasn't confirmed (K-094). Not
	// armed (the control plane doesn't restart it elsewhere on the strength of this host's
	// fence) until a later kill of it here is confirmed. The host is never rebooted for it.
	// The silo's FenceArmed KillFailed condition is the same mark across a restart, when this
	// map is empty (keepsKillFailed). killConfirmed: a kill this process has confirmed since.
	fenceFaulted  sync.Map
	killConfirmed sync.Map
	// removeConfirmed: silo UID → kri.ID: a kept copy a person confirmed the removal of (K-068,
	// keptcmd.go).
	removeConfirmed sync.Map
	keptWritten     atomic.Value // string: KeptFile as last written
	applied         appliedLog   // the resets and images applied here (applied.go, K-110)
	csInf           *informer.Informer
	csWake          chan struct{}
	csMu            sync.Mutex
	csHave          map[string]csDelivered // plugin\x00name → the version written and restarted for
	csSeen          map[string]csSeenDel   // cluster-secret name → the delete seen, and of which revision
}

func (a *Agent) stopsOnLoss(s *v1.Silo) (bool, time.Duration) {
	if a.StopsOnLoss != nil {
		return a.StopsOnLoss(s)
	}
	return s.StopsOnControlPlaneLoss()
}

// silence is how long the host has been without the control plane (zero before the agent runs).
// It counts on a one-node cluster too: a silo that asked to stop without the control plane stops
// whenever it's gone (§0.7 says not to ask for it there).
func (a *Agent) silence() time.Duration {
	if a.LastContact == nil || a.started.IsZero() {
		return 0
	}
	wall := a.Clock.Now().Sub(a.lastContact())
	if b, ok := a.contactBoot(); ok {
		d := boottime.Since(b) // K-072: not the wall clock alone, which a time server steps
		if a.hostIsVM() && wall > d {
			// K-093: a VM paused by its hypervisor (a snapshot, a live migration) may not count
			// the pause on its boot clock: either clock stops its silos. A wall clock stepped
			// forward stops them early too: on a VM, the safe side.
			d = wall
		}
		return d
	}
	return wall
}

func (a *Agent) hostIsVM() bool {
	a.isVMOnce.Do(func() {
		if a.HostIsVM != nil {
			a.isVM = a.HostIsVM()
		} else {
			a.isVM = detectVM()
		}
	})
	return a.isVM
}

// contactBoot is the last contact on the boot clock, where the worker gives it (LastContactBoot):
// this run's, else an earlier run's of the same boot (the record), else this run's start.
func (a *Agent) contactBoot() (time.Duration, bool) {
	if a.LastContactBoot == nil {
		return 0, false
	}
	if b, ok := a.LastContactBoot(); ok {
		return b, true
	}
	if a.fencePrev.ContactBoot > 0 && a.fencePrev.BootID != "" && a.fencePrev.BootID == boottime.ID() {
		return a.fencePrev.ContactBoot, true
	}
	return a.startedBoot, true
}

// inContact: the last contact is recent (well under the shortest after a silo may ask for).
func (a *Agent) inContact() bool { return a.silence() <= fence.DefaultAfter }

// mustStop reports whether s asked to be stopped on control-plane loss and the contact has been
// gone longer than its after.
func (a *Agent) mustStop(s *v1.Silo) bool {
	stop, after := a.stopsOnLoss(s)
	return stop && a.silence() > after
}

// lastContact is LastContact; with none yet in this run, what an earlier run recorded (a
// restart: never a fresh count), else when this run started (a host just booted, whose heartbeats
// haven't got through). Zero meant never fencing, which left its silos running while the control
// plane, counting from the last heartbeat stored before, recreated them elsewhere.
func (a *Agent) lastContact() time.Time {
	if last := a.LastContact(); !last.IsZero() {
		return last
	}
	if !a.fencePrev.LastContact.IsZero() {
		return a.fencePrev.LastContact
	}
	return a.started
}

// fence runs while the agent runs. Without contact it changes nothing but this (§0.7): a silo
// placed here that asked for it (onControlPlaneLoss: Stop) is killed once the contact is older
// than its after. A silo the agent doesn't know, or knows only as an older copy, is left alone.
// When the contact is back it looks at every silo again: the stopped ones start again, unless
// a person moved them meanwhile (those are removed here).
func (a *Agent) fence(ctx context.Context, e *engine.Engine) {
	ticks := a.tick(ctx, fence.CheckEvery)
	f := &fencing{a: a, inflight: map[string]time.Time{}, unconfirmed: map[string]string{}}
	watcherWas := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		a.writeFenceRecord(ctx)
		if a.inContact() {
			a.reportFenceFaults(ctx)
		}
		if live := a.watcherLive(); live != watcherWas {
			watcherWas = live
			a.resyncAll() // arm, or disarm, the opted-in silos now (armFence)
		}
		f.pass(ctx)
		if a.fenced.Load() && a.inContact() {
			a.fenced.Store(false)
			a.log("contact with the control plane is back: starting the silos stopped without it")
			unconfirmed, stopped := f.endOutage()
			a.reportUnconfirmed(ctx, unconfirmed)
			a.reportStopped(ctx, stopped)
			a.collectGarbage(ctx, e)
			for _, o := range a.silos.List() {
				s := o.(*v1.Silo)
				e.Changed(engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
			}
		}
	}
}

func (a *Agent) log(f string, args ...any) {
	if a.Log != nil {
		a.Log(f, args...)
	}
}

// Name implements engine.Controller.
func (a *Agent) Name() string { return "silo-agent" }

// Kind implements engine.Controller.
func (a *Agent) Kind() string { return "Silo" }

func idOf(s *v1.Silo) kri.ID { return kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID} }

// Run runs the agent until ctx ends.
func (a *Agent) Run(ctx context.Context) {
	a.historyAtStart = a.watermark().history() // read at start, before any answer is judged
	a.loadSeenDeletes()
	a.loadPlacedUnder()
	a.silos = informer.New(a.Client, "Silo")
	a.secrets, a.grants = informer.New(a.Client, "Secret"), informer.New(a.Client, "Grant")
	a.runCtx = ctx
	a.started, a.startedBoot = a.Clock.Now(), boottime.Now()
	a.endpoint = &Endpoint{Client: a.Client, HostName: a.HostName, Log: a.Log, Bound: a.Bound, Held: a.ControlPlaneHeld}
	if a.EndpointListen != "" {
		go a.endpoint.ServeEndpoint(ctx, a.EndpointListen)
	}
	e := engine.New(a.Clock)
	a.engine = e
	e.OnError = func(_ string, k engine.Key, err error, retry time.Duration) {
		a.log("silo %s: %v (retry in %v)", k, err, retry)
	}
	e.Register(a, engine.Options{Workers: 4})
	a.silos.AddHandler(func(k informer.Key) {
		key := engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}
		if o, ok := a.silos.Get(k.Namespace, k.Name); ok {
			if s := o.(*v1.Silo); s.DeletionTimestamp != nil {
				a.endStart(s.UID) // being deleted: a start of it under way here ends now
				a.interrupt(key, s.UID)
			} else if s.Status.Host != a.HostName {
				a.interrupt(key, s.UID) // placed elsewhere: what runs inside it here ends
			}
		} else {
			a.interrupt(key, "") // gone
		}
		e.Changed(key)
	})
	go a.silos.Run(ctx)
	go a.watchDeletes(ctx, e)
	go a.RunClusterSecrets(ctx)
	// Rotation fan-out: a secret or grant changing looks again at every silo here that receives
	// it (its files and env vars are written again, its endpoint and policy follow its grants).
	for kind, inf := range map[string]*informer.Informer{"Secret": a.secrets, "Grant": a.grants} {
		inf.AddHandler(func(k informer.Key) { a.fanOut(kind, k.Namespace, k.Name) })
		go inf.Run(ctx)
	}
	go a.RunTunnels(ctx)
	go a.runIngress(ctx)
	if a.FenceDir != "" {
		// What an earlier run of this agent recorded stands until this run knows better: a restart
		// while cut off must not make the watcher forget the last contact, or the silos.
		a.fencePrev, _ = fence.Read(a.FenceDir)
	}
	go a.fence(ctx, e)
	go a.watchControlPlane(ctx)
	go a.resync(ctx, e)
	go func() { // after the first sync, look for runtime silos the API no longer knows
		if a.silos.WaitSynced(ctx) {
			a.silosSynced.Store(true)
			a.collectGarbage(ctx, e)
		}
	}()
	// Nothing is reconciled before the agent knows the grants and secrets: with their caches still
	// empty (a restart) a silo would seem to receive nothing, and start, or run its init steps,
	// without its secrets.
	if !a.grants.WaitSynced(ctx) || !a.secrets.WaitSynced(ctx) {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Run(ctx)
	}()
	<-ctx.Done()
	a.awaitReconciles(done)
}

// ShutdownWait is how long a stopping agent waits for the reconciles under way to end (each ends
// at its next step: every runtime call takes the run's context). It is well inside systemd's
// stop timeout (90s), so kevasod exits by itself, saying what it left, rather than being killed.
// Nothing of a silo is stopped by the agent stopping: what was left is looked at again by the
// next run (a start's claim lapses, an init step left running is stopped and runs again).
const ShutdownWait = 30 * time.Second

// awaitReconciles waits for the engine's workers (done) once the run's context ended: at most
// ShutdownWait (Agent.ShutdownWait in tests), naming every 5s, and at the end, the reconciles
// still under way and for how long.
func (a *Agent) awaitReconciles(done <-chan struct{}) {
	wait := ShutdownWait
	if a.ShutdownWait > 0 {
		wait = a.ShutdownWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	every := time.NewTicker(5 * time.Second)
	defer every.Stop()
	for {
		select {
		case <-done:
			return
		case <-every.C:
			a.log("stopping: waiting for %s", a.underWay())
		case <-deadline.C:
			a.log("stopping after %s with reconciles under way (looked at again by the next run): %s", wait, a.underWay())
			return
		}
	}
}

// underWay lists the reconciles in progress and how long each has run.
func (a *Agent) underWay() string {
	var list []string
	a.inFlight.Range(func(k, v any) bool {
		list = append(list, fmt.Sprintf("%s (%s)", k.(engine.Key), time.Since(v.(time.Time)).Round(time.Second)))
		return true
	})
	sort.Strings(list)
	if len(list) == 0 {
		return "nothing (the engine's workers are ending)"
	}
	return strings.Join(list, ", ")
}

// ResyncEvery is how often the agent looks at every silo of its host again, events or not: a VM
// that died or a container stopped behind Kevaso's back is put back.
var ResyncEvery = 30 * time.Second

func (a *Agent) resync(ctx context.Context, e *engine.Engine) {
	every := ResyncEvery
	if a.Resync > 0 {
		every = a.Resync
	}
	ticks := a.tick(ctx, every)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
		a.resyncAll()
	}
}

// resyncAll looks at every silo of this host again.
func (a *Agent) resyncAll() {
	for _, o := range a.silos.List() {
		if s := o.(*v1.Silo); s.Status.Host == a.HostName {
			a.engine.Changed(engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
}

// collectGarbage enqueues every silo a runtime has, so ones deleted from the API while the agent
// was down get removed.
func (a *Agent) collectGarbage(ctx context.Context, e *engine.Engine) {
	a.pruneDeletes(ctx)
	for _, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			a.log("list %s: %v", rt.Info().Name, err)
			continue
		}
		for _, id := range ids {
			e.Changed(engine.Key{Kind: "Silo", Namespace: id.Namespace, Name: id.Name})
		}
	}
}

// Reconcile implements engine.Controller.
func (a *Agent) Reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	a.inFlight.Store(k, time.Now())
	defer a.inFlight.Delete(k)
	res, err := a.reconcile(ctx, k)
	if errors.Is(err, errPlacedElsewhere) {
		// The store places it on another host since this host's cache was filled: whatever was
		// under way stops here (nothing is started), and the cache brings the rest.
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return res, err
}

func (a *Agent) reconcile(ctx context.Context, k engine.Key) (engine.Result, error) {
	if a.ControlPlaneHeld() {
		return engine.Result{RequeueAfter: 5 * time.Second}, nil // §0.7: everything stays as it is
	}
	o, ok := a.silos.Get(k.Namespace, k.Name)
	var s *v1.Silo
	if ok {
		s = o.(*v1.Silo)
	}
	if s == nil || s.Status.Host != a.HostName || s.DeletionTimestamp != nil {
		if s != nil {
			a.endClaim(s.UID) // not starting here any more (a keeper's renewal refuses it anyway)
		}
		if err := a.removeEverywhere(ctx, k, s); err != nil {
			return engine.Result{}, err
		}
		if s != nil { // mounted, but its runtime copy never got made
			if err := a.unmountVolumes(ctx, s.UID, s); err != nil {
				return engine.Result{}, err
			}
			// Moved away from here: stopped and let go of, so the new host may start it.
			if _, ok := moves.Released(s.Status, a.HostName); ok && s.DeletionTimestamp == nil {
				a.log("%s/%s moved to %s: released here", s.Namespace, s.Name, s.Status.Host)
				return engine.Result{}, a.releaseMove(ctx, s)
			}
		}
		return engine.Result{}, nil
	}
	return a.whileHere(ctx, k, s, func(ctx context.Context) (engine.Result, error) { return a.runHere(ctx, k, s) })
}

// runHere drives s, placed here, towards running (whileHere: a delete of it, or its placement
// elsewhere, ends whatever of it is under way: a pull, a create, a start, a reset, its init steps).
func (a *Agent) runHere(ctx context.Context, k engine.Key, s *v1.Silo) (engine.Result, error) {
	if !moves.MayStart(s, a.HostName) {
		// Moving here: the old host stops it and lets go of its volumes first.
		return engine.Result{RequeueAfter: 2 * time.Second}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Ready", meta.ConditionFalse, "Moving", "waiting for "+s.Status.MovingFrom+" to stop it and let go", s.Generation, a.now())
		})
	}
	if a.mustStop(s) {
		return engine.Result{RequeueAfter: 5 * time.Second}, nil // cut off past its after: it asked not to run
	}
	// An older silo with the same name (deleted and re-created) must not linger next to it.
	if err := a.removeEverywhere(ctx, k, s); err != nil {
		return engine.Result{}, err
	}
	if err := a.armFence(ctx, s); err != nil {
		return engine.Result{}, err
	}
	rt, ok := a.Runtimes[s.Spec.Runtime]
	if !ok {
		return engine.Result{}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Phase = PhaseFailed
			setCond(st, "Ready", meta.ConditionFalse, "RuntimeMissing", "runtime "+s.Spec.Runtime+" isn't installed on "+a.HostName, s.Generation, a.now())
		})
	}
	if a.RuntimeReady != nil && !a.RuntimeReady(s.Spec.Runtime) {
		// Still installing (a boot, a new host): nothing starts yet, and the status says what's
		// true. A silo that doesn't run isn't Running (after a reboot it said so from before).
		if s.Status.Phase == PhaseRunning {
			if rs, err := rt.Status(ctx, idOf(s)); err == nil && rs.State != kri.Running {
				return engine.Result{RequeueAfter: 2 * time.Second}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
					st.Phase = PhaseStarting
					setCond(st, "Ready", meta.ConditionFalse, "NotRunning", "not running on "+a.HostName+" ("+string(rs.State)+"): started once runtime "+s.Spec.Runtime+" is installed", s.Generation, a.now())
				})
			}
		}
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	// Provider volumes first: attached by the control plane, formatted once and mounted here. Also
	// after a reboot, before the silo starts again.
	vols, ready, msg, err := a.mountVolumes(ctx, s)
	if err != nil {
		return engine.Result{}, err
	}
	if !ready {
		return engine.Result{RequeueAfter: volumeWait}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Ready", meta.ConditionFalse, "VolumesPending", msg, s.Generation, a.now())
		})
	}
	diskPath, ready, msg, err := a.mountRootDisk(ctx, s)
	if err != nil {
		return engine.Result{}, err
	}
	if !ready {
		return engine.Result{RequeueAfter: volumeWait}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Ready", meta.ConditionFalse, "VolumesPending", msg, s.Generation, a.now())
		})
	}
	id := idOf(s)
	rs, err := rt.Status(ctx, id)
	if err != nil {
		return engine.Result{}, err
	}
	if stopped, err := a.stopOrphanInit(ctx, rt, s, rs); err != nil || stopped {
		return engine.Result{RequeueAfter: time.Millisecond}, err
	}
	if restart, err := a.setVolumes(ctx, rt, s, rs.State, vols); err != nil || restart {
		return engine.Result{RequeueAfter: time.Millisecond}, err
	}
	if err := a.releaseDropped(ctx, rt, s, rs.State); err != nil {
		return engine.Result{}, err
	}
	image, resolved := imageOf(s)
	if rs.State != kri.Absent && resolved {
		// A new image, or a reset asked for: put it back onto the image, stop-first (design §0.4).
		if due, err := a.update(ctx, rt, s, image, vols, diskPath); err != nil || due {
			return engine.Result{RequeueAfter: time.Millisecond}, err
		}
	}
	switch rs.State {
	case kri.Absent:
		a.endClaim(s.UID) // nothing of it here: no start of it runs (review-batch3 C)
		if wait := a.createWait(s); wait > 0 {
			return engine.Result{RequeueAfter: wait}, nil // its last create failed: the backoff first
		}
		if wait, err := a.mayStartHere(ctx, s); wait || err != nil {
			return engine.Result{RequeueAfter: 2 * time.Second}, nil
		}
		mem, err := v1.ParseBytes(s.Spec.Resources.Memory)
		if err != nil {
			return engine.Result{}, err
		}
		disk, err := v1.ParseBytes(s.Spec.Disk.Size)
		if err != nil {
			return engine.Result{}, err
		}
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Phase = PhaseStarting
			setCond(st, "Ready", meta.ConditionFalse, "Creating", "creating on "+a.HostName, s.Generation, a.now())
		}); err != nil {
			return engine.Result{}, err
		}
		if err := a.recordForFence(s); err != nil {
			return engine.Result{}, err
		}
		digest, err := a.pull(ctx, rt, s, image)
		if err == nil {
			err = rt.Create(ctx, kri.Spec{ID: id, Image: image, CPU: s.Spec.Resources.CPU, Memory: mem, DiskBytes: disk,
				Volumes: vols, Command: s.Spec.Command(), DiskHostPath: diskPath})
		}
		if err != nil {
			wait := a.createFailed(s)
			_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, failReason(err, "CreateFailed"), err.Error()+" (trying again in "+wait.String()+")", s.Generation, a.now())
			})
			a.log("silo %s/%s: create: %v (trying again in %s)", s.Namespace, s.Name, err, wait)
			return engine.Result{RequeueAfter: wait}, nil
		}
		a.createBackoff.Delete(s.UID)
		a.recordApplied(s.UID, s.Spec.Reset, image) // a create satisfied this reset and image (K-127)
		return engine.Result{RequeueAfter: time.Millisecond}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Image = running(st.Image, s, image)
			st.Image.Digest = digest
		})
	case kri.Created, kri.Stopped:
		if wait, err := a.mayStartHere(ctx, s); wait || err != nil {
			a.endClaim(s.UID) // nothing of it runs, and nothing starts now: no claim stands for it
			return engine.Result{RequeueAfter: 2 * time.Second}, nil
		}
		if s.Status.Phase == PhaseRunning { // it stopped (a reboot, a VMM stopped): say so first
			if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseStarting
				setCond(st, "Ready", meta.ConditionFalse, "NotRunning", "not running on "+a.HostName+" ("+string(rs.State)+"): starting it again", s.Generation, a.now())
			}); err != nil {
				return engine.Result{}, err
			}
		}
		ic, initContainers := rt.(kri.InitContainers)
		if initContainers && s.Spec.Init != nil && len(s.Spec.Init.Steps) > 0 {
			// The steps are decided on what is stored (the cache may be behind this agent's own
			// write of a step's result: a step that failed, or is done, would run again).
			var cur v1.Silo
			if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
				return engine.Result{}, err
			}
			if cur.UID == s.UID && cur.Generation == s.Generation {
				sc := *s
				sc.Status.Init = cur.Status.Init
				s = &sc
			}
		}
		if _, ours := a.startedHere.LoadAndDelete(s.UID); ours && rs.State == kri.Stopped {
			// K-115, as the machines saw it: its Start succeeded and its main process ended by
			// itself (a command that isn't there exits at once; a VMM that exits). A failed start:
			// tried again after the backoff, with no claim meanwhile, as one whose Start failed.
			wait := a.backoffFailed(&a.startBackoff, s)
			a.log("silo %s/%s: it stopped by itself after its start (%s) (trying again in %s)", s.Namespace, s.Name, firstLineOf(rs.Message), wait)
			a.endClaim(s.UID)
			return engine.Result{RequeueAfter: wait}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, "Exited", "it stopped by itself after it was started on "+a.HostName+" (trying again in "+wait.String()+")", s.Generation, a.now())
			})
		}
		// K-115: nothing is claimed for a start that can't go on now. A failed init step stays
		// failed until the silo is reset or its spec changes (runSteps), and a start that failed
		// waits out its backoff: the agent's own writes (the claim above all) come back as events,
		// and each used to claim and try again at once.
		if initContainers && initFailed(s) {
			a.endClaim(s.UID)
			return engine.Result{}, nil
		}
		if wait := a.backoffWait(&a.startBackoff, s); wait > 0 {
			a.endClaim(s.UID)
			return engine.Result{RequeueAfter: wait}, nil
		}
		if initContainers && rs.State == kri.Stopped && s.Spec.Init != nil && s.Spec.Init.When == "everyBoot" && initDone(s) {
			// Init containers run again at every boot: the steps start over (a status write only).
			if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Init = nil }); err != nil {
				return engine.Result{}, err
			}
			return engine.Result{RequeueAfter: time.Millisecond}, nil
		}
		// Its policy is in the fence record before anything of it runs, never after: a fence must know it.
		if err := a.recordForFence(s); err != nil {
			return engine.Result{}, err
		}
		// K-088: the start claim before anything of the silo runs here or gets its secrets: an
		// init container is the silo's code, with its image, volumes and secrets. Kept fresh, across
		// reconciles, until it is reported Running here (claimKeeper); a renewal that finds it placed
		// elsewhere, or the fence, ends whatever of its start runs.
		if err := a.claimStart(ctx, s); err != nil {
			return a.lostClaim(s, err)
		}
		kp := a.keepClaim(s)
		ended := func(why, err error) (engine.Result, error) {
			a.settleClaim(ctx, rt, s)
			return a.startEnded(s, why, err)
		}
		sctx, claimKept := kp.within(ctx)
		defer func() { _ = claimKept() }()
		hs, hostSecrets := rt.(kri.HostSecrets)
		if hostSecrets {
			// Its file and env secrets are there before anything of it starts (init containers too).
			if err := a.deliverFromHost(sctx, hs, s, true); err != nil {
				return ended(claimKept(), err)
			}
		}
		if initContainers {
			// Init containers: the steps run before the main process, each in its own container.
			done, err := a.runSteps(sctx, s, func(ctx context.Context, step v1.InitStep, out io.Writer) (int, error) {
				return ic.RunInit(ctx, id, kri.InitStep{Name: step.Name, Shell: step.Shell, Run: step.Run}, out)
			})
			if err != nil || !done {
				return ended(claimKept(), err)
			}
		}
		if !hostSecrets {
			a.delivered.Delete(s.UID) // a fresh boot: an empty /run, its secrets are written again
		}
		// Every start begins its probes afresh: startup's deadline counts from this boot.
		a.probed.Delete(s.UID)
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Probes, st.StartedAt = nil, nil }); err != nil {
			return ended(claimKept(), err)
		}
		if why := claimKept(); why != nil {
			return ended(why, nil)
		}
		// Claimed once more right before the start, with no renewal in flight: the start follows a
		// claim that applied on what is stored at this moment. Renewals go on during the Start.
		if err := kp.claimNow(ctx); err != nil {
			a.settleClaim(ctx, rt, s)
			return a.lostClaim(s, err)
		}
		stctx, startKept := kp.within(ctx)
		err := a.startSilo(stctx, rt, s)
		if why := startKept(); why != nil {
			return ended(why, err) // placed elsewhere or fenced meanwhile: the removal or the fence ends what came up
		}
		if err != nil {
			a.settleClaim(ctx, rt, s)
			wait := a.backoffFailed(&a.startBackoff, s)
			a.log("silo %s/%s: start: %v (trying again in %s)", s.Namespace, s.Name, err, wait)
			return engine.Result{RequeueAfter: wait}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				setCond(st, "Ready", meta.ConditionFalse, failReason(err, "StartFailed"), err.Error()+" (trying again in "+wait.String()+")", s.Generation, a.now())
			})
		}
		a.startedHere.Store(s.UID, struct{}{})
		if _, ok := rt.(kri.InitContainers); !ok && s.Spec.Init != nil && s.Spec.Init.When == "everyBoot" {
			if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Init = nil }); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	case kri.Failed:
		// Its machine failed (a VMM that exited, a dead container): started again, like a
		// liveness restart, with the same backoff and count (status.restarts).
		//
		// The start that got it here has ended (nothing of it runs: Failed is a process gone):
		// its claim isn't kept while it waits out the backoff, where each renewal would be a new
		// claim, resetting the host's silence and blocking a restart elsewhere and
		// --confirm-fenced while nothing starts (review-batch3 C). A restart claims again.
		a.endClaim(s.UID)
		now := a.now()
		if wait := probes.RestartWait(s.Status.Restarts, now); wait > 0 {
			return engine.Result{RequeueAfter: wait}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", rs.Message+" (starting it again in "+wait.Round(time.Second).String()+")", s.Generation, now)
			})
		}
		if wait, err := a.mayStartHere(ctx, s); wait || err != nil {
			return engine.Result{RequeueAfter: 2 * time.Second}, nil
		}
		r := probes.Restarted(s.Status.Restarts, now)
		a.log("silo %s/%s failed (%s): starting it again (restart %d)", s.Namespace, s.Name, firstLineOf(rs.Message), r.Count)
		// K-117: steps that run at every boot run after a crash restart too (they started over).
		everyBoot := s.Spec.Init != nil && s.Spec.Init.When == "everyBoot" && len(s.Spec.Init.Steps) > 0
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Restarts, st.Phase, st.StartedAt, st.Probes = r, PhaseStarting, nil, nil
			if everyBoot {
				st.Init = nil
			}
			setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", rs.Message+" (starting it again: restart "+strconv.Itoa(r.Count)+")", s.Generation, now)
		}); err != nil {
			return engine.Result{}, err
		}
		a.probed.Delete(s.UID)
		if err := a.claimStart(ctx, s); err != nil {
			return a.lostClaim(s, err)
		}
		kp := a.keepClaim(s) // kept fresh until it is reported Running
		if ic, ok := rt.(kri.InitContainers); ok && everyBoot {
			// Init containers run before the main process, as at any start.
			fresh := *s
			fresh.Status.Init = nil
			ictx, initKept := kp.within(ctx)
			done, err := a.runSteps(ictx, &fresh, func(ctx context.Context, step v1.InitStep, out io.Writer) (int, error) {
				return ic.RunInit(ctx, id, kri.InitStep{Name: step.Name, Shell: step.Shell, Run: step.Run}, out)
			})
			if why := initKept(); why != nil || err != nil || !done {
				a.settleClaim(ctx, rt, s)
				return a.startEnded(s, why, err)
			}
		}
		// Claimed once more right before the main process, as at a first start. Every-boot init
		// can outlast a renewal; the start follows a claim that applied on what is stored now.
		if err := kp.claimNow(ctx); err != nil {
			a.settleClaim(ctx, rt, s)
			return a.lostClaim(s, err)
		}
		stctx, startKept := kp.within(ctx)
		err := a.startSilo(stctx, rt, s)
		if why := startKept(); why != nil {
			a.settleClaim(ctx, rt, s)
			return a.startEnded(s, why, err)
		}
		if err != nil {
			a.settleClaim(ctx, rt, s)
			return engine.Result{RequeueAfter: probes.Backoff(r.Backoff)}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", "starting it again failed: "+err.Error(), s.Generation, a.now())
			})
		}
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	}

	return a.whileItRuns(ctx, k, rt, s, func(inside context.Context) (engine.Result, error) {
		return a.reconcileRunning(ctx, inside, rt, s, rs, vols, image)
	})
}

// reconcileRunning looks after a silo its runtime says runs. Everything it runs inside the silo
// (through Exec: its guest's mounts, its deliveries, init steps, probes, daemons, upkeep) runs
// under inside, which ends once the silo no longer runs, or is deleted or placed elsewhere
// (whileItRuns); ctx is the reconcile's own, for status writes and the restart of a liveness
// failure.
func (a *Agent) reconcileRunning(ctx, inside context.Context, rt kri.Runtime, s *v1.Silo, rs kri.Status, vols []kri.Volume, image string) (engine.Result, error) {
	// Running: its guest mounts its volumes (VMs), the silo's policy (runtimes that enforce grants
	// themselves), its local endpoint, its file and env secrets (written by the host), then init
	// steps, then Ready. Its panes are fetched while it runs.
	//
	// Until it is reported Running here, its start claim is kept fresh (a VM's and an OpenShell
	// sandbox's init steps run now, through Exec). A start this run of the agent didn't make (kevasod
	// restarted while it booted) is claimed again first.
	sctx, claimKept := inside, func() error { return nil }
	if s.Status.Phase != PhaseRunning && !a.reportedRunning(s) { // (a cache behind our own Running write: not a new start)
		kp := a.claimKept(s)
		if kp == nil {
			if err := a.claimStart(ctx, s); err != nil {
				return a.lostClaim(s, err)
			}
			kp = a.keepClaim(s)
		}
		sctx, claimKept = kp.within(inside)
		defer func() { _ = claimKept() }()
	} else {
		a.endClaim(s.UID)
	}
	starting := func(err error) (engine.Result, error) {
		if why := claimKept(); why != nil {
			a.settleClaim(ctx, rt, s)
			return a.startEnded(s, why, err)
		}
		return engine.Result{}, err
	}
	if err := a.mountGuestVolumes(sctx, rt, s, vols); err != nil {
		return starting(err)
	}
	if pr, ok := rt.(kri.Policied); ok {
		if err := a.applyPolicy(sctx, pr, s); err != nil {
			return starting(err)
		}
	}
	if err := a.keepEndpoint(ctx, rt, s, rs.Address); err != nil {
		return starting(err)
	}
	if err := a.deliver(sctx, rt, s); err != nil {
		return starting(err)
	}
	a.keepPanes(ctx, s, rs.Address)
	if done, err := a.runInit(sctx, rt, s); err != nil || !done {
		return starting(err)
	}
	if why := claimKept(); why != nil {
		return starting(nil)
	}
	// Probes (design §0.6), if it has any: Started, Ready and Degraded follow them. Without any,
	// it's Started and Ready now, and nothing else is ensured.
	startedAt := a.now()
	if s.Status.StartedAt != nil {
		startedAt = *s.Status.StartedAt
	}
	po := a.probe(inside, rt, s, rs.Address, startedAt)
	if inside.Err() != nil {
		return engine.Result{}, context.Cause(inside) // not a probe's failure: it stopped running, or left here
	}
	if po.restart {
		return engine.Result{RequeueAfter: time.Millisecond}, a.restartForLiveness(ctx, rt, s, po)
	}
	again := po.next
	// Its mount-reach volumes answering, or not (a JuiceFS volume whose database is down hangs).
	dirs := a.mountVolumeDirs(s)
	bad, pending := a.probeVolumes(dirs)
	if len(dirs) > 0 {
		next := a.probeEvery()
		if pending {
			next = a.probeTimeout()
		}
		if again == 0 || next < again {
			again = next
		}
	}
	if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		a.volumesResponding(s, st, bad, dirs)
		st.Phase, st.SiloIP = PhaseRunning, rs.Address
		if st.Image == nil || st.Image.Running == "" {
			st.Image = running(st.Image, s, image) // created before images were recorded
		}
		if st.StartedAt == nil {
			st.StartedAt = &startedAt
		}
		applyProbes(st, s, po, a.now())
		if c := meta.FindCondition(st.Conditions, "Ready"); c != nil && c.Reason == "Running" {
			c.Message = "running on " + a.HostName
		}
	}); err != nil {
		return engine.Result{}, err
	}
	a.endClaim(s.UID) // reported Running: the heartbeat speaks for the host now
	a.reported.Store(s.UID, s.Generation)
	// Ready or not, its daemons and upkeep are kept (a daemon may be what makes it ready).
	keepAgain, err := a.keepInside(inside, rt, s)
	if err != nil {
		return engine.Result{}, err
	}
	if keepAgain > 0 && (again == 0 || keepAgain < again) {
		again = keepAgain
	}
	return engine.Result{RequeueAfter: again}, nil
}

// imageOf is what the silo's runtime gets: what the control plane resolved its source to (a
// VMImage's version, an inline disk, a registry reference). resolved is false while a changed
// source waits for the control plane: the
// silo keeps what it has until then.
func imageOf(s *v1.Silo) (image string, resolved bool) {
	im := s.Status.Image
	switch {
	case im == nil || im.Ref == "":
		return s.Spec.From(), true // nothing resolved yet: the name as it is
	case im.From == s.Spec.From():
		return im.Ref, true
	}
	return im.Ref, false
}

// running records that the silo now runs image, with its current reset applied.
func running(cur *v1.SiloImage, s *v1.Silo, image string) *v1.SiloImage {
	next := &v1.SiloImage{From: s.Spec.From(), Ref: image}
	if cur != nil {
		next.From, next.Ref = cur.From, cur.Ref
		if next.Ref == "" {
			next.From, next.Ref = s.Spec.From(), image
		}
	}
	if cur != nil && cur.Running == image {
		next.Digest = cur.Digest // what was pulled for it (Create and Reset set a new one)
	}
	next.Running, next.Reset = image, s.Spec.Reset
	return next
}

// update resets the silo onto image when that's due: its image changed, or spec.reset did. Always
// stop-first: the old copy is stopped completely before the new one exists, so two never run
// (StartFirst needs a disk clone, which comes with moves). Volumes are kept; the disk or container
// is fresh from the image, so firstBoot init steps run again. due says it acted (or must wait).
func (a *Agent) update(ctx context.Context, rt kri.Runtime, s *v1.Silo, image string, vols []kri.Volume, diskPath string) (bool, error) {
	due := func(s *v1.Silo) bool {
		cur := s.Status.Image
		return cur != nil && cur.Running != "" && (cur.Running != image || cur.Reset != s.Spec.Reset)
	}
	if !due(s) {
		return false, nil
	}
	// The cache may be behind our own last write (a reset just done): decide on the stored silo.
	var fresh v1.Silo
	if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &fresh); err != nil {
		return true, client.IgnoreNotFound(err)
	}
	if fresh.UID != s.UID || fresh.Generation != s.Generation || !due(&fresh) {
		return true, nil // changed under us, or already done: look again with what's stored
	}
	cur := s.Status.Image
	what := "a reset"
	if cur.Running != image {
		what = "image " + image
	}
	applied, err := a.alreadyApplied(s.UID, s.Spec.Reset, image)
	if err != nil {
		// K-127: the record of what this host applied can't be read. It is not empty: a request
		// the store says is due (a restored status) is not applied again while that's so.
		msg := "the record of resets applied here can't be read (" + err.Error() + "): a reset is not applied again, its disk is kept"
		a.log("silo %s/%s: %s is not applied: %s", s.Namespace, s.Name, what, msg)
		if werr := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Updated", meta.ConditionFalse, "AppliedRecordUnreadable", msg, s.Generation, a.now())
		}); werr != nil {
			return true, werr
		}
		return true, errors.New(msg)
	}
	if applied {
		// K-110: this host made the disk afresh for this very request already; the store's status
		// is from before (a control plane restored from a backup taken while it was due). Nothing
		// is wiped again: the status is brought up to what was done.
		a.log("silo %s/%s: %s was applied here already (this host's record): its disk is kept, the status says so again", s.Namespace, s.Name, what)
		return true, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Image = running(st.Image, s, image)
			setCond(st, "Updated", meta.ConditionTrue, "AlreadyApplied", what+" was applied on "+a.HostName+" already: nothing done again", s.Generation, a.now())
		})
	}
	rr, ok := rt.(kri.Resetter)
	if !ok {
		return true, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Updated", meta.ConditionFalse, "ResetUnsupported", "runtime "+s.Spec.Runtime+" can't reset a silo: "+what+" waits", s.Generation, a.now())
		})
	}
	// The pull first, while the old copy still runs: a registry that refuses leaves it running
	// (and Ready), with Updated saying why the update waits.
	digest, err := a.pull(ctx, rt, s, image)
	if err != nil {
		_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Updated", meta.ConditionFalse, failReason(err, "ResetFailed"), err.Error()+" (still running the old image)", s.Generation, a.now())
		})
		return true, fmt.Errorf("reset onto %s: %w", image, err)
	}
	// The gate (review, check-then-act claim 1): the pull took a while, and the reset or the image
	// may have been taken back meanwhile. Right before the disk is touched, a compare-and-swap on
	// what is stored now: the same silo, generation and placement, the reset still due onto this
	// image. Anything else, a conflict included, stops nothing: it looks again.
	if ok, err := a.gateReset(ctx, s, image, due, func(st *v1.SiloStatus) {
		st.Phase = PhaseStarting
		setCond(st, "Ready", meta.ConditionFalse, "Updating", "stopping for "+what+" (StopFirst; volumes kept)", s.Generation, a.now())
	}); err != nil || !ok {
		if err == nil {
			a.log("silo %s/%s: its reset or image changed while the image was pulled: nothing stopped, looking again", s.Namespace, s.Name)
		}
		return true, err
	}
	id := idOf(s)
	a.stoppedByUs(s.UID)
	if err := rt.Stop(ctx, id); err != nil {
		return true, fmt.Errorf("stop for %s: %w", what, err)
	}
	mem, err := v1.ParseBytes(s.Spec.Resources.Memory)
	if err != nil {
		return true, err
	}
	disk, err := v1.ParseBytes(s.Spec.Disk.Size)
	if err != nil {
		return true, err
	}
	// The gate again, the last thing before the disk or container is made afresh (review claim
	// 3): the stop took a while too (cloud-hypervisor waits up to 30s for the guest). A runtime
	// that can (gatedResetter) asks it inside its Reset, right before it removes anything; for
	// the others it is taken right before Reset. A request that changed meanwhile leaves the
	// silo stopped with its disk, and it starts again as it is.
	gate := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second) // a runtime may hold its lock meanwhile
		defer cancel()
		ok, err := a.gateReset(ctx, s, image, due, func(st *v1.SiloStatus) {
			setCond(st, "Ready", meta.ConditionFalse, "Updating", "stopped for "+what+": its disk is made afresh now (volumes kept)", s.Generation, a.now())
		})
		if err == nil && !ok {
			err = errResetTakenBack
		}
		return err
	}
	spec := kri.Spec{ID: id, Image: image, CPU: s.Spec.Resources.CPU, Memory: mem, DiskBytes: disk,
		Volumes: vols, Command: s.Spec.Command(), DiskHostPath: diskPath}
	if g, ok := rr.(gatedResetter); ok {
		err = g.ResetGated(ctx, spec, gate)
	} else if err = gate(ctx); err == nil {
		err = rr.Reset(ctx, spec)
	}
	if errors.Is(err, errResetTakenBack) {
		a.log("silo %s/%s: its reset or image changed while it stopped: its disk is kept, looking again", s.Namespace, s.Name)
		return true, nil
	}
	if err != nil {
		_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Updated", meta.ConditionFalse, failReason(err, "ResetFailed"), err.Error(), s.Generation, a.now())
		})
		return true, fmt.Errorf("reset onto %s: %w", image, err)
	}
	// Recorded here before the store is told (K-110): a restored status replays nothing.
	a.recordApplied(s.UID, s.Spec.Reset, image)
	a.delivered.Delete(s.UID) // a fresh disk: its secrets and CA are written again, and its mounts
	a.guestMounted.Delete(s.UID)
	a.log("silo %s/%s: reset onto %s (%s)", s.Namespace, s.Name, image, what)
	return true, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Image, st.Init, st.SiloIP = running(st.Image, s, image), nil, ""
		st.Image.Digest = digest
		setCond(st, "Updated", meta.ConditionTrue, "Reset", "reset onto "+image+" (stop-first, volumes kept)", s.Generation, a.now())
	})
}

// gatedResetter is a runtime whose Reset asks gate right before it removes or overwrites
// anything of the silo (its root disk, its containers), after its own stop: an error from gate
// ends the reset with nothing removed, and is returned as is.
type gatedResetter interface {
	ResetGated(ctx context.Context, spec kri.Spec, gate func(context.Context) error) error
}

// errResetTakenBack: the reset gate found the request changed (taken back, another image, the
// silo changed or placed elsewhere): nothing is removed.
var errResetTakenBack = errors.New("the reset or the image changed since it was asked for")

// gateReset writes mutate onto the stored silo only if it is still s, at s's generation, placed
// here, resolving to image, with the reset due (due), in one compare-and-swap: ok says it applied.
func (a *Agent) gateReset(ctx context.Context, s *v1.Silo, image string, due func(*v1.Silo) bool, mutate func(*v1.SiloStatus)) (bool, error) {
	var cur v1.Silo
	if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if im, resolved := imageOf(&cur); cur.UID != s.UID || cur.Generation != s.Generation || cur.DeletionTimestamp != nil ||
		cur.Status.Host != a.HostName || !resolved || im != image || !due(&cur) {
		return false, nil // the caller says which gate refused
	}
	mutate(&cur.Status)
	cur.Status.Routing = routing.Silo(cur.Spec, cur.Status)
	if err := a.Client.UpdateStatus(ctx, &cur); client.IsConflict(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// runInit runs the init steps that haven't run yet inside the running silo (through Exec).
func (a *Agent) runInit(ctx context.Context, rt kri.Runtime, s *v1.Silo) (bool, error) {
	return a.runSteps(ctx, s, func(ctx context.Context, step v1.InitStep, out io.Writer) (int, error) {
		return rt.Exec(ctx, idOf(s), kri.ExecRequest{Command: command(step), Stdout: out, Stderr: out})
	})
}

// initDone reports whether every init step of the silo has succeeded.
func initDone(s *v1.Silo) bool {
	if s.Spec.Init == nil {
		return true
	}
	done := map[string]bool{}
	for _, st := range s.Status.Init {
		done[st.Name] = st.State == "Done"
	}
	for _, step := range s.Spec.Init.Steps {
		if !done[step.Name] {
			return false
		}
	}
	return true
}

// runSteps runs the init steps that haven't run yet with run, recording each one. It returns
// done=true once every step succeeded (or there are none); a failed step stops the rest and marks
// InitFailed.
func (a *Agent) runSteps(ctx context.Context, s *v1.Silo, run func(context.Context, v1.InitStep, io.Writer) (int, error)) (bool, error) {
	if s.Spec.Init == nil || len(s.Spec.Init.Steps) == 0 {
		return true, nil
	}
	results := map[string]v1.StepStatus{}
	for _, st := range s.Status.Init {
		results[st.Name] = st
	}
	// spec.init.timeout (K-117): the steps a start runs, together, within it (on the agent's
	// clock). A step still running then is stopped and recorded failed.
	var timedOut atomic.Bool
	if d, err := time.ParseDuration(s.Spec.Init.Timeout); err == nil && d > 0 {
		tctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		t := a.Clock.AfterFunc(d, func() { timedOut.Store(true); cancel(errInitTimeout) })
		defer t.Stop()
		ctx = tctx
	}
	for _, step := range s.Spec.Init.Steps {
		switch results[step.Name].State {
		case "Done":
			continue
		case "Failed":
			return false, nil // stays InitFailed until the silo is reset or the spec changes
		}
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Phase = PhaseStarting
			st.Init = upsertStep(st.Init, v1.StepStatus{Name: step.Name, State: "Running"})
			setCond(st, "Ready", meta.ConditionFalse, "Initializing", "init step "+step.Name, s.Generation, a.now())
		}); err != nil {
			return false, err
		}
		start := a.now()
		var out bytes.Buffer
		code, err := run(ctx, step, &out)
		if timedOut.Load() {
			// Its own deadline, not a start that ended: recorded failed (a reset or a spec change
			// runs it again), with what it printed.
			res := v1.StepStatus{Name: step.Name, State: "Failed", Duration: a.now().Sub(start).Round(time.Second).String()}
			if werr := a.setStatus(context.WithoutCancel(ctx), s, func(st *v1.SiloStatus) {
				st.Init = upsertStep(st.Init, res)
				setCond(st, "InitFailed", meta.ConditionTrue, "StepTimedOut",
					fmt.Sprintf("step %s was still running when spec.init.timeout (%s) ran out: %s", step.Name, s.Spec.Init.Timeout, tail(out.String(), 300)), s.Generation, a.now())
			}); werr != nil {
				return false, werr
			}
			return false, nil
		}
		if ctx.Err() != nil || a.mustStop(s) {
			// Stopped, not failed (K-088): its start ended (placed elsewhere, the fence killed
			// it). Nothing is recorded; it runs again with the next start.
			return false, fmt.Errorf("init step %s stopped: %w", step.Name, errors.Join(context.Cause(ctx), err))
		}
		if err != nil {
			return false, fmt.Errorf("init step %s: %w", step.Name, err)
		}
		res := v1.StepStatus{Name: step.Name, State: "Done", ExitCode: &code, Duration: a.now().Sub(start).Round(time.Second).String()}
		if code != 0 {
			res.State = "Failed"
		}
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Init = upsertStep(st.Init, res)
			if code != 0 {
				setCond(st, "InitFailed", meta.ConditionTrue, "StepFailed",
					fmt.Sprintf("step %s exited %d: %s", step.Name, code, tail(out.String(), 300)), s.Generation, a.now())
			}
		}); err != nil {
			return false, err
		}
		if code != 0 {
			return false, nil
		}
	}
	return true, nil
}

// errInitTimeout ends the steps of a start that ran past spec.init.timeout.
var errInitTimeout = errors.New("spec.init.timeout ran out")

// command turns a step into argv: `shell -c run` (sh by default; python3, bash, … work the same).
func command(step v1.InitStep) []string {
	shell := step.Shell
	if shell == "" {
		shell = "sh"
	}
	return []string{shell, "-c", step.Run}
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

func upsertStep(steps []v1.StepStatus, s v1.StepStatus) []v1.StepStatus {
	for i := range steps {
		if steps[i].Name == s.Name {
			steps[i] = s
			return steps
		}
	}
	return append(steps, s)
}

func (a *Agent) now() time.Time { return a.Clock.Now().UTC().Truncate(time.Second) }

func setCond(st *v1.SiloStatus, typ string, status meta.ConditionStatus, reason, msg string, gen int64, now time.Time) {
	meta.SetCondition(&st.Conditions, meta.Condition{Type: typ, Status: status, Reason: reason, Message: msg, ObservedGeneration: gen}, now)
}

// setStatus re-reads the silo from the API, applies mutate to its status and writes it, retrying
// on conflicts (the scheduler or a user may have written in between).
func (a *Agent) setStatus(ctx context.Context, s *v1.Silo, mutate func(*v1.SiloStatus)) error {
	return a.writeStatus(ctx, s, mutate, false)
}

// setStatusAway is setStatus for the one write a host makes on a silo placed elsewhere now: its
// volumes unmounted here.
func (a *Agent) setStatusAway(ctx context.Context, s *v1.Silo, mutate func(*v1.SiloStatus)) error {
	return a.writeStatus(ctx, s, mutate, true)
}

// writeStatus writes s's status as mutate makes it, onto what is stored now. Never on a silo the
// store places on another host (K-015: a cache from before says it's still here), unless away.
func (a *Agent) writeStatus(ctx context.Context, s *v1.Silo, mutate func(*v1.SiloStatus), away bool) error {
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return err
		}
		if cur.UID != s.UID {
			return nil // deleted and re-created: not the silo we were working on
		}
		if !away && cur.Status.Host != a.HostName {
			return errPlacedElsewhere // placed elsewhere since this host's cache was filled: not ours to write
		}
		if cur.Status.Host == a.HostName {
			a.notePlaced(cur.UID) // the store read now places it here (K-112, K-126)
		}
		before := statusKey(cur.Status)
		mutate(&cur.Status)
		cur.Status.Routing = routing.Silo(cur.Spec, cur.Status) // always as its status says now
		if statusKey(cur.Status) == before {
			return nil
		}
		err := a.Client.UpdateStatus(ctx, &cur)
		if client.IsConflict(err) {
			continue
		}
		return err
	}
	return errors.New("status kept changing; will retry")
}

// createBackoff is a silo's failed creates (a pull of an image that isn't there, say): each
// waits before the next, 5s doubling up to 5m, for as long as its spec stays the same. Its
// status writes come back as changes; without this each started the next try at once.
type createBackoff struct {
	generation int64
	delay      time.Duration
	until      time.Time
}

// createFailed records a failed create of s and says how long until the next.
func (a *Agent) createFailed(s *v1.Silo) time.Duration { return a.backoffFailed(&a.createBackoff, s) }

// createWait is how long s's next create must still wait (0: now).
func (a *Agent) createWait(s *v1.Silo) time.Duration { return a.backoffWait(&a.createBackoff, s) }

// backoffFailed records a failed try of s in m (createBackoff, startBackoff) and says how long
// until the next: twice the last wait, unless the last failure is long past (it ran well since).
func (a *Agent) backoffFailed(m *sync.Map, s *v1.Silo) time.Duration {
	b := createBackoff{generation: s.Generation, delay: 5 * time.Second}
	if o, ok := m.Load(s.UID); ok {
		if prev := o.(createBackoff); prev.generation == s.Generation && a.Clock.Now().Sub(prev.until) < backoffForgetAfter {
			b.delay = min(2*prev.delay, 5*time.Minute)
		}
	}
	b.until = a.Clock.Now().Add(b.delay)
	m.Store(s.UID, b)
	return b.delay
}

// backoffForgetAfter: a failure this long after the last try's wait ended starts the backoff over.
const backoffForgetAfter = 10 * time.Minute

// backoffWait is how long s's next try must still wait by m (0: now).
func (a *Agent) backoffWait(m *sync.Map, s *v1.Silo) time.Duration {
	o, ok := m.Load(s.UID)
	if !ok {
		return 0
	}
	b := o.(createBackoff)
	if b.generation != s.Generation {
		m.Delete(s.UID) // a new spec: try it now
		return 0
	}
	return max(b.until.Sub(a.Clock.Now()), 0)
}

// initFailed reports whether an init step of s is recorded failed: its start goes no further
// until the silo is reset or its spec changes (runSteps).
func initFailed(s *v1.Silo) bool {
	if s.Spec.Init == nil {
		return false
	}
	state := map[string]string{}
	for _, st := range s.Status.Init {
		state[st.Name] = st.State
	}
	for _, step := range s.Spec.Init.Steps {
		switch state[step.Name] {
		case "Done":
			continue
		case "Failed":
			return true
		}
		return false // runSteps runs this one next
	}
	return false
}

// stoppedByUs: this agent stops silo uid itself now (an update, a liveness restart, new volumes,
// an orphan init step, the fence): found stopped next, it didn't stop by itself.
func (a *Agent) stoppedByUs(uid string) { a.startedHere.Delete(uid) }

// errPlacedElsewhere: a status write or a start claim found the silo placed on another host (or
// moved, deleted, re-made, or changed) since it was read here. Whoever gets it stops what it was
// doing for that silo; above all, it doesn't start it.
var errPlacedElsewhere = errors.New("the control plane places this silo elsewhere now")

// errReplaced: the store has another silo of that name (a new UID).
var errReplaced = fmt.Errorf("%w (the store has another silo of that name)", errPlacedElsewhere)

// errUnknown: the store doesn't have the silo being started here (NotFound), or has another of
// that name: its start ends. It is not a delete seen here (review-batch4 claim 1): a control
// plane restored from an older backup (a new history this worker accepts), or a system node
// behind, says the same of a silo nobody deleted. The copy is then kept, stopped, with its disk
// and volumes, and listed (removeEverywhere), unless the delete watch saw its delete.
var errUnknown = fmt.Errorf("%w (the control plane doesn't know it now)", errPlacedElsewhere)

// unknownNow says whether err, from a read or write of s during its start, shows the store without
// s: not found, or another silo of that name. Never, by itself, a delete.
func unknownNow(err error) bool {
	return client.IsNotFound(err) || errors.Is(err, errReplaced) || errors.Is(err, errUnknown)
}

// ConditionStartClaim is the silo condition a host writes just before it starts the silo (its
// start claim, K-015): written against the exact version it read, so it applies only if nothing
// changed the silo since, placement above all. The host starts it only if the write applied. The
// control plane doesn't place a silo elsewhere while a fresh claim by a host in contact stands
// (StartClaimFresh; the control lane's half).
const ConditionStartClaim = "StartClaim"

// StartClaimFresh is how long a start claim stands.
const StartClaimFresh = 30 * time.Second

// ClaimRefreshEvery is how often a host writes its start claim anew while it starts a silo that
// takes long (its init steps): well inside StartClaimFresh, so the control plane always sees a
// standing claim while anything of the silo runs here before its main process (K-088).
const ClaimRefreshEvery = StartClaimFresh / 3

// claimStart wins the right to start s here, now: a compare-and-swap on the stored silo of the
// version this host reads, requiring it to be the same silo, at the same generation, placed here,
// free to start here, and not being deleted. Any other outcome, a conflict included, is
// errPlacedElsewhere: the start is abandoned.
func (a *Agent) claimStart(ctx context.Context, s *v1.Silo) error {
	err := a.writeClaim(ctx, s, false)
	if errors.Is(err, errClaimConflict) {
		return errPlacedElsewhere
	}
	return err
}

// writeClaim is one claim: a read, the checks, a compare-and-swap (errClaimConflict if it lost).
//
// renewal: a renewal of a start under way (its init step running) goes on through a spec edit (a
// newer generation), placed here all the same (K-117: an edit killed the step, which then ran
// again); the start's next claim, right before the main process, is at the generation it read.
func (a *Agent) writeClaim(ctx context.Context, s *v1.Silo, renewal bool) error {
	var cur v1.Silo
	if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
		return err
	}
	if cur.UID != s.UID {
		return errReplaced
	}
	sameSpec := cur.Generation == s.Generation || renewal && cur.Generation > s.Generation
	if cur.DeletionTimestamp != nil || !sameSpec || !moves.MayStart(&cur, a.HostName) {
		return errPlacedElsewhere
	}
	claim := startClaim(a.HostName, s.Generation, a.Clock.Now().UTC())
	removeCondition(&cur.Status, ConditionStartClaim)
	removeCondition(&cur.Status, fence.ConditionStopped)         // a report of an earlier start: this one isn't stopped
	cur.Status.Conditions = append(cur.Status.Conditions, claim) // always a change: the write is the claim
	cur.Status.Routing = routing.Silo(cur.Spec, cur.Status)
	err := a.Client.UpdateStatus(ctx, &cur) // against cur's resourceVersion: applies only if nothing changed it
	if client.IsConflict(err) {
		return errClaimConflict
	}
	return err
}

// startClaim is the claim host writes before it starts a silo of generation gen. The control
// plane reads the host out of its message (silo.StartClaimOf): "starting on HOST at TIME".
func startClaim(host string, gen int64, now time.Time) meta.Condition {
	return meta.Condition{Type: ConditionStartClaim, Status: meta.ConditionTrue, Reason: "Starting",
		Message: "starting on " + host + " at " + now.Format(time.RFC3339Nano), ObservedGeneration: gen,
		LastTransitionTime: now.Truncate(time.Second)}
}

// lostClaim is the end of a start this host didn't win: nothing is started; the init steps and
// deliveries it made go with the copy when the cache shows the silo elsewhere.
func (a *Agent) lostClaim(s *v1.Silo, err error) (engine.Result, error) {
	if unknownNow(err) {
		// Nothing of a start abandoned here keeps running; what it made stays (a delete only the
		// delete watch sees removes it).
		a.log("not starting %s/%s: the control plane doesn't know it now (%v): what of it runs here is stopped, its disk and volumes are kept unless its delete is seen", s.Namespace, s.Name, err)
		a.stopAbandoned(s)
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	if errors.Is(err, errPlacedElsewhere) {
		a.log("not starting %s/%s: its start claim didn't apply (the control plane changed or placed it elsewhere since it was read here)", s.Namespace, s.Name)
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return engine.Result{RequeueAfter: 2 * time.Second}, err // the claim couldn't be written: nothing starts
}

// stopAbandoned stops what of s runs here after its start was abandoned because the store
// doesn't know it now: nothing of the silo runs on the strength of a start that ended. Its disk,
// volumes and runtime copy stay.
func (a *Agent) stopAbandoned(s *v1.Silo) {
	rt, ok := a.Runtimes[s.Spec.Runtime]
	if !ok {
		return
	}
	ctx := a.runCtx
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background() // the agent stops: what came up is stopped all the same
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := rt.Stop(ctx, idOf(s)); err != nil && !errors.Is(err, kri.ErrNotFound) {
		a.log("%s/%s: stopping what of its abandoned start runs: %v (the next look tries again)", s.Namespace, s.Name, err)
		a.abandoned.Store(s.UID, struct{}{})
		return
	}
	a.abandoned.Delete(s.UID)
}

// mayStartHere reads the stored silo before anything of it is created or started here (K-015):
// the cache can be from before a cut, when the silo was placed here and has since been started
// elsewhere. Only the same silo, at the generation the cache has, placed here, free to start
// here, and not being deleted, goes on; anything else waits for the cache (wait true), and so
// does a read that fails (an error): nothing new starts on a guess.
func (a *Agent) mayStartHere(ctx context.Context, s *v1.Silo) (wait bool, err error) {
	var cur v1.Silo
	if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
		return true, err
	}
	ok := cur.UID == s.UID && cur.DeletionTimestamp == nil && cur.Generation == s.Generation && moves.MayStart(&cur, a.HostName)
	if !ok {
		if _, noted := a.staleNoted.LoadOrStore(s.UID, struct{}{}); !noted {
			a.log("not starting %s/%s: the control plane places it on %q now (this host's copy of it is from before); waiting for it",
				s.Namespace, s.Name, cur.Status.Host)
		}
		return true, nil
	}
	a.staleNoted.Delete(s.UID)
	return false, nil
}

// releaseMove tells the control plane this host has let go of a silo that moved away.
func (a *Agent) releaseMove(ctx context.Context, s *v1.Silo) error {
	for range 5 {
		var cur v1.Silo // what's stored: the release is judged against it, not our copy
		if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return err
		}
		if cur.UID != s.UID {
			return nil
		}
		st, ok := moves.Released(cur.Status, a.HostName)
		if !ok {
			return nil
		}
		cur.Status = st
		err := a.Client.UpdateStatus(ctx, &cur)
		if !client.IsConflict(err) {
			return err
		}
	}
	return errors.New("status kept changing; will retry")
}

// removeEverywhere deletes the silo from every runtime that has it. For a silo still in the API
// but no longer ours (or being deleted), only the runtime copy is removed.
func (a *Agent) removeEverywhere(ctx context.Context, k engine.Key, s *v1.Silo) error {
	listed := map[string]bool{} // the UIDs of this name some runtime lists
	for rtName, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if id.Namespace != k.Namespace || id.Name != k.Name {
				continue
			}
			listed[id.UID] = true
			if s != nil && s.Status.Host == a.HostName && s.DeletionTimestamp == nil && id.UID == s.UID {
				a.keptNoted.Delete(id.UID) // known and placed here (again): no longer a kept copy
				a.dropRemovalConfirmation(id.UID)
				continue
			}
			// Not in the API (or replaced by another of the same name) and no delete of it seen
			// here: keep it, running, its disk and volumes untouched (design §0.7, K-004).
			if s == nil || id.UID != s.UID {
				if !a.seenHere(id.UID) && !a.removalConfirmed(id.UID) {
					if _, again := a.abandoned.Load(id.UID); again {
						if err := rt.Stop(ctx, id); err != nil && !errors.Is(err, kri.ErrNotFound) {
							return err
						}
						a.abandoned.Delete(id.UID)
					}
					if _, logged := a.keptNoted.LoadOrStore(id.UID, keptCopy{runtime: rtName, id: id, name: keptName(id, rt.Info().Name)}); !logged {
						a.log("keeping %s on %s: the control plane doesn't know it and no delete of it was seen here; it keeps running with its disk and volumes (nothing is removed without a delete)",
							id, rt.Info().Name)
					}
					continue
				}
				a.keptNoted.Delete(id.UID)
			}
			// The same silo, placed elsewhere or being deleted as this host's cache has it. The
			// copy here holds its disk (a microVM's Delete removes its root volume), so it goes
			// only on proof read now: a delete the store holds, a delete seen here, or a handoff
			// from this host. Anything else (a restart elsewhere, a restored or older store, a
			// person's --confirm-fenced move) stops it and keeps it.
			remove, why, err := a.mayRemove(ctx, id)
			if err != nil {
				return err
			}
			if !remove {
				if why == "" {
					a.keptNoted.Delete(id.UID) // placed here again: no longer a kept copy
					continue                   // the reconcile goes on with it
				}
				if err := rt.Stop(ctx, id); err != nil && !errors.Is(err, kri.ErrNotFound) {
					return err
				}
				if _, logged := a.keptNoted.LoadOrStore(id.UID, keptCopy{runtime: rtName, id: id, name: keptName(id, rt.Info().Name+", stopped: "+why)}); !logged {
					a.log("keeping %s on %s, stopped, with its disk and volumes: %s (nothing is removed without a delete or a handoff from here)", id, rt.Info().Name, why)
				}
				continue
			}
			a.keptNoted.Delete(id.UID)
			// A handoff of a silo with volumes on this host's disks: deleting the copy would delete
			// them (every runtime removes a silo's local volumes on Delete). A volume is kept data
			// (design §0.3): admission never lets such a silo be recreated elsewhere, so this
			// shouldn't happen; if it does, stop the copy and keep it.
			if local := hostLocalVolumes(s); why == whyHandoff && len(local) > 0 {
				if _, seen := a.heldBack.LoadOrStore(id.UID, struct{}{}); !seen {
					a.log("%s isn't placed here any more (host %q), but keeps local volume(s) %s here: stopped, not removed (delete the silo to remove them)",
						id, s.Status.Host, strings.Join(local, ", "))
					if err := rt.Stop(ctx, id); err != nil && !errors.Is(err, kri.ErrNotFound) {
						a.heldBack.Delete(id.UID)
						return err
					}
				}
				continue
			}
			a.heldBack.Delete(id.UID)
			a.log("removing %s from %s", id, rt.Info().Name)
			if a.endpoint != nil {
				a.endpoint.Unregister(id.UID)
			}
			a.stopPanes(id.UID)
			a.delivered.Delete(id.UID)
			a.guestMounted.Delete(id.UID)
			a.kept.Delete(id.UID)
			if err := rt.Stop(ctx, id); err != nil && !errors.Is(err, kri.ErrNotFound) {
				return err
			}
			if err := rt.Delete(ctx, id); err != nil {
				return err
			}
			if err := a.unmountVolumes(ctx, id.UID, s); err != nil {
				return err
			}
			a.forgetDelete(id.UID) // nothing of it left here
			a.forgetApplied(id.UID)
			a.forgetPlaced(id.UID)
			a.removalDone(id.UID)
		}
	}
	return a.stopUnlisted(ctx, k, s, listed)
}

const whyHandoff = "handed off from here"

// keptCopy is a copy kept here that the control plane doesn't know (keptNoted): the runtime that
// holds it (its key in Runtimes), and how it is listed.
type keptCopy struct {
	runtime, name string
	// unlisted: a copy its runtime doesn't list (its state can't be read, K-105), found by id.
	unlisted bool
	id       kri.ID
}

// keptName is how a kept copy is listed on the Host (KeptSilos): its name, the start of its UID
// (two kept copies of one name, a silo deleted and made again, are told apart), and what.
func keptName(id kri.ID, what string) string {
	uid := id.UID
	if len(uid) > 8 {
		uid = uid[:8]
	}
	return id.String() + " uid " + uid + " (" + what + ")"
}

// mayRemove decides, on the stored silo read now, whether this host may remove its copy id (its
// disk with it): yes for a delete the store holds or this host saw, or a handoff from this host
// (why says which); no, with why, for anything else; no with why "" when the store places it here
// again (the cache was behind).
func (a *Agent) mayRemove(ctx context.Context, id kri.ID) (remove bool, why string, err error) {
	var cur v1.Silo
	m := a.watermark().mark()
	err = a.Client.Get(ctx, "Silo", id.Namespace, id.Name, &cur)
	if err == nil || client.IsNotFound(err) {
		// Only an answer this worker accepts, of the history it trusts now, is proof of anything
		// here: a held answer (a system node behind), or one across a restore, removes nothing.
		if !a.watermark().acceptedSince(m) {
			return false, "", errors.New("the control plane's answer about " + id.String() + " can't be acted on (held, or another history): nothing removed")
		}
	}
	if a.removalConfirmed(id.UID) {
		// K-068: a person confirmed its removal (kvoadm host kept --remove): that is the proof,
		// unless the store places this very silo here (it isn't a kept copy then).
		if err == nil && cur.UID == id.UID && cur.Status.Host == a.HostName && cur.DeletionTimestamp == nil {
			a.dropRemovalConfirmation(id.UID)
			return false, "", nil
		}
		if err != nil && !client.IsNotFound(err) {
			return false, "", err
		}
		return true, "its removal was confirmed by a person (kvoadm host kept --remove)", nil
	}
	seen := a.seenHere(id.UID)
	switch {
	case client.IsNotFound(err) || err == nil && cur.UID != id.UID:
		if seen {
			return true, "its delete was seen here", nil
		}
		return false, "the control plane doesn't know it and no delete of it was seen here", nil
	case err != nil:
		return false, "", err
	case cur.DeletionTimestamp != nil:
		return true, "being deleted", nil
	case cur.Status.Host == a.HostName:
		return false, "", nil
	case cur.Status.MovingFrom == a.HostName:
		if under := a.historyPlaced(id.UID); under != a.watermark().history() {
			// K-112: this host ran it under another history than the one that hands it off now (a
			// restore since): a handoff replayed from a backup, not an order. Stopped and kept.
			return false, "handed off by a control plane of another history (" + a.watermark().history() + ") than the one it ran here under (" + under + "): a restore's replay, not an order", nil
		}
		return true, whyHandoff, nil
	}
	return false, fmt.Sprintf("placed on %q with no handoff from this host", cur.Status.Host), nil
}

// historyPlaced is the history under which this host last found the silo uid placed here, including
// one recorded on disk by an earlier run (K-126). With no record, it is the history trusted when
// this run began. After a new history, a copy already here with no record was not placed under
// that history: the handoff is a replay until the store places it here under the new one.
func (a *Agent) historyPlaced(uid string) string {
	if v, ok := a.placedUnder.Load(uid); ok {
		return v.(string)
	}
	cur := a.watermark().history()
	if cur != a.historyAtStart || a.placedOther {
		if a.historyAtStart != cur {
			return a.historyAtStart
		}
		return historyNotRecorded
	}
	return a.historyAtStart
}

// hostLocalVolumes are the names of s's volumes on this host's own disks (class local).
func hostLocalVolumes(s *v1.Silo) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, v := range s.Spec.Volumes {
		if v.Class == "" || v.Class == v1.VolumeLocal {
			out = append(out, v.Name)
		}
	}
	return out
}

// fanOut looks again at the local silos a changed secret or grant reaches.
func (a *Agent) fanOut(kind, namespace, name string) {
	var local []*v1.Silo
	for _, o := range a.silos.List() {
		if s := o.(*v1.Silo); s.Status.Host == a.HostName {
			local = append(local, s)
		}
	}
	var grants []*v1.Grant
	for _, o := range a.grants.List() {
		grants = append(grants, o.(*v1.Grant))
	}
	for _, s := range Affected(local, grants, kind, namespace, name) {
		if a.engine != nil {
			a.engine.Changed(engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
		}
	}
}

// siloPolicy is the silo's grants as a runtime policy, with the credentials it injects.
func (a *Agent) siloPolicy(ctx context.Context, s *v1.Silo) (kri.Policy, []string, error) {
	var resp client.BrokerResponse
	if err := a.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: s.Namespace, Name: s.Name, UID: s.UID, Host: a.HostName,
		Request: client.BrokerRequest{Op: client.OpInjections}}, &resp); err != nil {
		return kri.Policy{}, nil, fmt.Errorf("credentials for the policy: %w", err)
	}
	if resp.Error != "" {
		return kri.Policy{}, nil, fmt.Errorf("credentials for the policy: %s", resp.Error)
	}
	p, problems := policy.For(s, a.grantList(), resp.Injections)
	return p, problems, nil
}

func clearPolicy(p kri.Policy) {
	for _, c := range p.Credentials {
		clear(c.Value)
	}
}

// stagePolicy writes a stager's policy file from the silo's grants. Other runtimes have nothing
// to write. A silo with no grants is written as deny-all.
func (a *Agent) stagePolicy(ctx context.Context, rt kri.Runtime, s *v1.Silo) error {
	st, ok := rt.(kri.PolicyStager)
	if !ok {
		return nil
	}
	p, _, err := a.siloPolicy(ctx, s)
	if err != nil {
		return err
	}
	defer clearPolicy(p)
	return st.StagePolicy(ctx, idOf(s), p)
}

// startSilo writes the policy file, then starts. A new OpenShell sandbox is created with that
// file, so its first moment already has the silo's grants, including a grant that changed while
// the silo was stopped. A silo with no grants is created deny-all.
func (a *Agent) startSilo(ctx context.Context, rt kri.Runtime, s *v1.Silo) error {
	if err := a.stagePolicy(ctx, rt, s); err != nil { // the policy file is current before the sandbox is created or started
		return err
	}
	return rt.Start(ctx, idOf(s))
}

// applyPolicy gives a runtime that enforces grants itself the silo's policy, with the credentials
// it injects (from the control plane, for silos on this host), and says in a condition what it
// couldn't enforce.
func (a *Agent) applyPolicy(ctx context.Context, rt kri.Policied, s *v1.Silo) error {
	p, problems, err := a.siloPolicy(ctx, s)
	if err != nil {
		return err
	}
	defer clearPolicy(p)
	if err := rt.SetPolicy(ctx, idOf(s), p); err != nil {
		_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "PolicyApplied", meta.ConditionFalse, "NotApplied", err.Error(), s.Generation, a.now()) // a failed push is not reported as applied
		})
		return fmt.Errorf("policy: %w", err)
	}
	return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		if len(problems) > 0 {
			setCond(st, "PolicyApplied", meta.ConditionFalse, "NotEnforceable", strings.Join(problems, "; "), s.Generation, a.now())
			return
		}
		setCond(st, "PolicyApplied", meta.ConditionTrue, "Applied", fmt.Sprintf("%d endpoints, %d injected credentials", len(p.Egress), len(p.Credentials)), s.Generation, a.now())
	})
}

var _ engine.Controller = (*Agent)(nil)

// keepEndpoint registers the silo with its host's local endpoint while one of its grants needs it
// (ADR 0009), at the address its runtime gave it, and forgets it otherwise. Runtimes that enforce
// grants themselves (OpenShell) have no ordinary network to reach it by: a silo there that would
// need it says so in LocalEndpoint.
func (a *Agent) keepEndpoint(ctx context.Context, rt kri.Runtime, s *v1.Silo, address string) error {
	needs := v1.NeedsEndpoint(s, a.grantList())
	addr, err := netip.ParseAddr(address)
	_, policied := rt.(kri.Policied)
	status, reason, msg := meta.ConditionTrue, "Serving", "http://"+v1.EndpointAddress+" (header "+v1.EndpointHeader+": 1)"
	switch {
	case !needs:
		a.endpoint.Unregister(s.UID)
		if findCond(s.Status.Conditions, "LocalEndpoint") == nil {
			return nil
		}
		return a.setStatus(ctx, s, func(st *v1.SiloStatus) { removeCondition(st, "LocalEndpoint") })
	case policied:
		a.endpoint.Unregister(s.UID)
		status, reason, msg = meta.ConditionFalse, "NotSupported", "runtime "+s.Spec.Runtime+" has no local endpoint yet: broker secrets, signing and port leases aren't reachable from this silo"
	case err != nil:
		a.endpoint.Unregister(s.UID)
		status, reason, msg = meta.ConditionFalse, "NoAddress", "the runtime gave the silo no address"
	default:
		a.endpoint.Register(addr, idOf(s))
	}
	if c := findCond(s.Status.Conditions, "LocalEndpoint"); c != nil && c.Status == status && c.Reason == reason && c.Message == msg {
		return nil // as it says already
	}
	return a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		setCond(st, "LocalEndpoint", status, reason, msg, s.Generation, a.now())
	})
}

func findCond(cs []meta.Condition, typ string) *meta.Condition {
	for i := range cs {
		if cs[i].Type == typ {
			return &cs[i]
		}
	}
	return nil
}

func removeCondition(st *v1.SiloStatus, typ string) {
	out := st.Conditions[:0]
	for _, c := range st.Conditions {
		if c.Type != typ {
			out = append(out, c)
		}
	}
	st.Conditions = out
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// watchDeletes records every silo delete the control plane announces while this agent is
// watching (its UID), then looks at the silo again: only a delete seen here removes a silo's data.
// A delete made while the watch was down is never seen, and that silo is kept (design §0.7).
func (a *Agent) watchDeletes(ctx context.Context, e *engine.Engine) {
	for ctx.Err() == nil {
		// From now on only (a list's revision): a watch from nothing replays deletes made before
		// this agent was watching, which it never saw.
		//
		// The stream is of the history accepted when it opened (its list and its answer judged,
		// neither refused): its deletes are recorded under that history, and once another is
		// accepted (a restore) it is opened anew, so a delete of the old history is never taken
		// as one of the new (review-batch4 claim 1).
		var ch <-chan client.Event
		wctx, stopWatch := context.WithCancel(ctx)
		wm := a.watermark()
		m0 := wm.mark()
		l, err := a.Client.List(wctx, "Silo", "")
		if err == nil {
			ch, err = a.Client.Watch(wctx, "Silo", "", l.Metadata.ResourceVersion)
		}
		hist := wm.history()
		if err == nil && !wm.acceptedSince(m0) {
			stopWatch()
			if ch != nil {
				for range ch { // drained: its goroutine ends with the stream
				}
			}
			if now := wm.mark(); now.refusals == m0.refusals && !a.ControlPlaneHeld() {
				continue // only a history accepted meanwhile (a first contact, a restore): open it again now
			}
			ch, err = nil, errors.New("the delete watch opened on an answer this worker doesn't act on")
		}
		if err == nil {
			for ev := range ch {
				if wm.mark().histories != m0.histories {
					break // another history accepted: this stream's deletes are of the old one
				}
				if ev.Type != "DELETED" || a.ControlPlaneHeld() {
					continue // a delete from a control plane this worker doesn't trust removes nothing
				}
				o, _, err := v1.Decode(ev.Object)
				if err != nil {
					continue
				}
				m := o.GetObjectMeta()
				s, _ := o.(*v1.Silo)
				a.sawDelete(kri.ID{Namespace: m.Namespace, Name: m.Name, UID: m.UID}, s != nil && a.mayHaveHere(ctx, s), hist)
				a.interrupt(engine.Key{Kind: "Silo", Namespace: m.Namespace, Name: m.Name}, m.UID)
				e.Changed(engine.Key{Kind: "Silo", Namespace: m.Namespace, Name: m.Name})
			}
		}
		stopWatch()
		if ch != nil {
			for range ch { // drained: its goroutine ends with the stream
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
