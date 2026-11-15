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
	seenDeleted   sync.Map
	keptNoted     sync.Map // silo UID → what it is: kept, listed on the Host (ConditionKeptSilos)
	engine        *engine.Engine
	cp            *Watermark // the control plane this worker trusts (watermark.go); via watermark()
	cpOnce        sync.Once
	staleNoted    sync.Map // silo UID → logged once that its cache was stale at a start
	createBackoff sync.Map // silo UID → createBackoff
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
	if b, ok := a.contactBoot(); ok {
		return boottime.Since(b) // K-072: never the wall clock, which a time server steps
	}
	return a.Clock.Now().Sub(a.lastContact())
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
	t := time.NewTicker(fence.CheckEvery)
	defer t.Stop()
	killed := map[string]bool{} // in this outage
	watcherWas := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.writeFenceRecord(ctx)
		if a.inContact() {
			a.reportFenceFaults(ctx)
		}
		if live := a.watcherLive(); live != watcherWas {
			watcherWas = live
			a.resyncAll() // arm, or disarm, the opted-in silos now (armFence)
		}
		for _, rt := range a.Runtimes {
			ids, err := rt.List(ctx)
			if err != nil {
				continue
			}
			for _, id := range ids {
				o, ok := a.silos.Get(id.Namespace, id.Name)
				if !ok || killed[id.UID] {
					continue
				}
				s := o.(*v1.Silo)
				if s.UID != id.UID || !a.mustStop(s) {
					continue
				}
				_, after := a.stopsOnLoss(s)
				a.fenced.Store(true)
				a.log("no contact with the control plane for over %s: stopping %s (onControlPlaneLoss: Stop, after %s)", after, id, after)
				kctx, cancel := context.WithTimeout(ctx, fence.KillWithin)
				// Killed, not stopped gracefully: it asked not to run on without the control plane.
				err := kri.Kill(kctx, rt, id)
				if err == nil {
					if st, serr := rt.Status(kctx, id); serr == nil && st.State == kri.Running {
						err = errors.New("it still runs")
					}
				}
				cancel()
				if err != nil {
					a.log("fence %s: %v (trying again)", id, err) // done only once confirmed (K-067)
					continue
				}
				killed[id.UID] = true
			}
		}
		if a.fenced.Load() && a.inContact() {
			a.fenced.Store(false)
			clear(killed)
			a.log("contact with the control plane is back: starting the silos stopped without it")
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
	a.watermark() // read at start, before any answer is judged
	a.silos = informer.New(a.Client, "Silo")
	a.secrets, a.grants = informer.New(a.Client, "Secret"), informer.New(a.Client, "Grant")
	a.runCtx = ctx
	a.started, a.startedBoot = a.Clock.Now(), boottime.Now()
	a.endpoint = &Endpoint{Client: a.Client, HostName: a.HostName, Log: a.Log, Bound: a.Bound}
	if a.EndpointListen != "" {
		go a.endpoint.ServeEndpoint(ctx, a.EndpointListen)
	}
	e := engine.New(a.Clock)
	a.engine = e
	e.OnError = func(_ string, k engine.Key, err error, retry time.Duration) {
		a.log("silo %s: %v (retry in %v)", k, err, retry)
	}
	e.Register(a, engine.Options{Workers: 4})
	a.silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	go a.silos.Run(ctx)
	go a.watchDeletes(ctx, e)
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
	e.Run(ctx)
}

// ResyncEvery is how often the agent looks at every silo of its host again, events or not: a VM
// that died or a container stopped behind Kevaso's back is put back.
var ResyncEvery = 30 * time.Second

func (a *Agent) resync(ctx context.Context, e *engine.Engine) {
	t := time.NewTicker(ResyncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
	if restart, err := a.setVolumes(ctx, rt, s, rs.State, vols); err != nil || restart {
		return engine.Result{RequeueAfter: time.Millisecond}, err
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
		return engine.Result{RequeueAfter: time.Millisecond}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Image = running(st.Image, s, image)
			st.Image.Digest = digest
		})
	case kri.Created, kri.Stopped:
		if wait, err := a.mayStartHere(ctx, s); wait || err != nil {
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
		hs, hostSecrets := rt.(kri.HostSecrets)
		if hostSecrets {
			// Its file and env secrets are there before anything of it starts (init containers too).
			if err := a.deliverFromHost(ctx, hs, s, true); err != nil {
				return engine.Result{}, err
			}
		}
		if ic, ok := rt.(kri.InitContainers); ok {
			// Init containers: the steps run before the main process, each in its own container.
			if rs.State == kri.Stopped && s.Spec.Init != nil && s.Spec.Init.When == "everyBoot" && initDone(s) {
				if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Init = nil }); err != nil {
					return engine.Result{}, err
				}
				return engine.Result{RequeueAfter: time.Millisecond}, nil
			}
			done, err := a.runSteps(ctx, s, func(ctx context.Context, step v1.InitStep, out io.Writer) (int, error) {
				return ic.RunInit(ctx, id, kri.InitStep{Name: step.Name, Shell: step.Shell, Run: step.Run}, out)
			})
			if err != nil || !done {
				return engine.Result{}, err
			}
		}
		// Its policy is in the fence record before it runs, never after: a fence must know it.
		if err := a.recordForFence(s); err != nil {
			return engine.Result{}, err
		}
		if !hostSecrets {
			a.delivered.Delete(s.UID) // a fresh boot: an empty /run, its secrets are written again
		}
		// Every start begins its probes afresh: startup's deadline counts from this boot.
		a.probed.Delete(s.UID)
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Probes, st.StartedAt = nil, nil }); err != nil {
			return engine.Result{}, err
		}
		if err := a.claimStart(ctx, s); err != nil {
			return a.lostClaim(s, err)
		}
		if err := rt.Start(ctx, id); err != nil {
			return engine.Result{}, err
		}
		if _, ok := rt.(kri.InitContainers); !ok && s.Spec.Init != nil && s.Spec.Init.When == "everyBoot" {
			if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) { st.Init = nil }); err != nil {
				return engine.Result{}, err
			}
		}
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	case kri.Failed:
		// Its machine failed (a VMM that exited, a dead container): started again, like a
		// liveness restart, with the same backoff and count (status.restarts).
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
		if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Restarts, st.Phase, st.StartedAt, st.Probes = r, PhaseStarting, nil, nil
			setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", rs.Message+" (starting it again: restart "+strconv.Itoa(r.Count)+")", s.Generation, now)
		}); err != nil {
			return engine.Result{}, err
		}
		a.probed.Delete(s.UID)
		if err := a.claimStart(ctx, s); err != nil {
			return a.lostClaim(s, err)
		}
		if err := rt.Start(ctx, id); err != nil {
			return engine.Result{RequeueAfter: probes.Backoff(r.Backoff)}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", "starting it again failed: "+err.Error(), s.Generation, a.now())
			})
		}
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	}

	// Running: its guest mounts its volumes (VMs), the silo's policy (runtimes that enforce grants
	// themselves), its local endpoint, its file and env secrets (written by the host), then init
	// steps, then Ready. Its panes are fetched while it runs.
	if err := a.mountGuestVolumes(ctx, rt, s, vols); err != nil {
		return engine.Result{}, err
	}
	if pr, ok := rt.(kri.Policied); ok {
		if err := a.applyPolicy(ctx, pr, s); err != nil {
			return engine.Result{}, err
		}
	}
	if err := a.keepEndpoint(ctx, rt, s, rs.Address); err != nil {
		return engine.Result{}, err
	}
	if err := a.deliver(ctx, rt, s); err != nil {
		return engine.Result{}, err
	}
	a.keepPanes(ctx, s, rs.Address)
	if done, err := a.runInit(ctx, rt, s); err != nil || !done {
		return engine.Result{}, err
	}
	// Probes (design §0.6), if it has any: Started, Ready and Degraded follow them. Without any,
	// it's Started and Ready now, and nothing else is ensured.
	startedAt := a.now()
	if s.Status.StartedAt != nil {
		startedAt = *s.Status.StartedAt
	}
	po := a.probe(ctx, rt, s, rs.Address, startedAt)
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
	// Ready or not, its daemons and upkeep are kept (a daemon may be what makes it ready).
	keepAgain, err := a.keepInside(ctx, rt, s)
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
	if err := a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Phase = PhaseStarting
		setCond(st, "Ready", meta.ConditionFalse, "Updating", "stopping for "+what+" (StopFirst; volumes kept)", s.Generation, a.now())
	}); err != nil {
		return true, err
	}
	id := idOf(s)
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
	if err := rr.Reset(ctx, kri.Spec{ID: id, Image: image, CPU: s.Spec.Resources.CPU, Memory: mem, DiskBytes: disk,
		Volumes: vols, Command: s.Spec.Command(), DiskHostPath: diskPath}); err != nil {
		_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			setCond(st, "Updated", meta.ConditionFalse, failReason(err, "ResetFailed"), err.Error(), s.Generation, a.now())
		})
		return true, fmt.Errorf("reset onto %s: %w", image, err)
	}
	a.delivered.Delete(s.UID) // a fresh disk: its secrets and CA are written again, and its mounts
	a.guestMounted.Delete(s.UID)
	a.log("silo %s/%s: reset onto %s (%s)", s.Namespace, s.Name, image, what)
	return true, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Image, st.Init, st.SiloIP = running(st.Image, s, image), nil, ""
		st.Image.Digest = digest
		setCond(st, "Updated", meta.ConditionTrue, "Reset", "reset onto "+image+" (stop-first, volumes kept)", s.Generation, a.now())
	})
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
func (a *Agent) createFailed(s *v1.Silo) time.Duration {
	b := createBackoff{generation: s.Generation, delay: 5 * time.Second}
	if o, ok := a.createBackoff.Load(s.UID); ok {
		if prev := o.(createBackoff); prev.generation == s.Generation {
			b.delay = min(2*prev.delay, 5*time.Minute)
		}
	}
	b.until = a.Clock.Now().Add(b.delay)
	a.createBackoff.Store(s.UID, b)
	return b.delay
}

// createWait is how long s's next create must still wait (0: now).
func (a *Agent) createWait(s *v1.Silo) time.Duration {
	o, ok := a.createBackoff.Load(s.UID)
	if !ok {
		return 0
	}
	b := o.(createBackoff)
	if b.generation != s.Generation {
		a.createBackoff.Delete(s.UID) // a new spec: try it now
		return 0
	}
	return max(b.until.Sub(a.Clock.Now()), 0)
}

// errPlacedElsewhere: a status write or a start claim found the silo placed on another host (or
// moved, deleted, re-made, or changed) since it was read here. Whoever gets it stops what it was
// doing for that silo; above all, it doesn't start it.
var errPlacedElsewhere = errors.New("the control plane places this silo elsewhere now")

// ConditionStartClaim is the silo condition a host writes just before it starts the silo (its
// start claim, K-015): written against the exact version it read, so it applies only if nothing
// changed the silo since, placement above all. The host starts it only if the write applied. The
// control plane doesn't place a silo elsewhere while a fresh claim by a host in contact stands
// (StartClaimFresh; the control lane's half).
const ConditionStartClaim = "StartClaim"

// StartClaimFresh is how long a start claim stands.
const StartClaimFresh = 30 * time.Second

// claimStart wins the right to start s here, now: a compare-and-swap on the stored silo of the
// version this host reads, requiring it to be the same silo, at the same generation, placed here,
// free to start here, and not being deleted. Any other outcome, a conflict included, is
// errPlacedElsewhere: the start is abandoned.
func (a *Agent) claimStart(ctx context.Context, s *v1.Silo) error {
	var cur v1.Silo
	if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
		return err
	}
	if cur.UID != s.UID || cur.DeletionTimestamp != nil || cur.Generation != s.Generation || !moves.MayStart(&cur, a.HostName) {
		return errPlacedElsewhere
	}
	claim := startClaim(a.HostName, s.Generation, a.Clock.Now().UTC())
	removeCondition(&cur.Status, ConditionStartClaim)
	cur.Status.Conditions = append(cur.Status.Conditions, claim) // always a change: the write is the claim
	cur.Status.Routing = routing.Silo(cur.Spec, cur.Status)
	err := a.Client.UpdateStatus(ctx, &cur) // against cur's resourceVersion: applies only if nothing changed it
	if client.IsConflict(err) {
		return errPlacedElsewhere
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
	if errors.Is(err, errPlacedElsewhere) {
		a.log("not starting %s/%s: its start claim didn't apply (the control plane changed or placed it elsewhere since it was read here)", s.Namespace, s.Name)
		return engine.Result{RequeueAfter: 2 * time.Second}, nil
	}
	return engine.Result{RequeueAfter: 2 * time.Second}, err // the claim couldn't be written: nothing starts
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
	for _, rt := range a.Runtimes {
		ids, err := rt.List(ctx)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if id.Namespace != k.Namespace || id.Name != k.Name {
				continue
			}
			if s != nil && s.Status.Host == a.HostName && s.DeletionTimestamp == nil && id.UID == s.UID {
				continue
			}
			// Not in the API (or replaced by another of the same name) and no delete of it seen
			// here: keep it, running, its disk and volumes untouched (design §0.7, K-004).
			if s == nil || id.UID != s.UID {
				if _, seen := a.seenDeleted.Load(id.UID); !seen {
					if _, logged := a.keptNoted.LoadOrStore(id.UID, id.String()+" ("+rt.Info().Name+")"); !logged {
						a.log("keeping %s on %s: the control plane doesn't know it and no delete of it was seen here; it keeps running with its disk and volumes (nothing is removed without a delete)",
							id, rt.Info().Name)
					}
					continue
				}
				a.keptNoted.Delete(id.UID)
			}
			// The same silo, placed elsewhere but not deleted, with volumes on this host's disks:
			// deleting the copy would delete them (every runtime removes a silo's local volumes on
			// Delete). A volume is kept data (design §0.3): admission never lets such a silo be
			// recreated elsewhere, so this shouldn't happen; if it does, stop the copy and keep it.
			if local := hostLocalVolumes(s); s != nil && s.DeletionTimestamp == nil && id.UID == s.UID && len(local) > 0 {
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
		}
	}
	return nil
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

// applyPolicy gives a runtime that enforces grants itself the silo's policy, with the credentials
// it injects (from the control plane, for silos on this host), and says in a condition what it
// couldn't enforce.
func (a *Agent) applyPolicy(ctx context.Context, rt kri.Policied, s *v1.Silo) error {
	var resp client.BrokerResponse
	if err := a.Client.Call(ctx, http.MethodPost, client.PathAgentBroker, client.AgentBrokerRequest{
		Namespace: s.Namespace, Name: s.Name, UID: s.UID, Host: a.HostName,
		Request: client.BrokerRequest{Op: client.OpInjections}}, &resp); err != nil {
		return fmt.Errorf("credentials for the policy: %w", err)
	}
	if resp.Error != "" {
		return fmt.Errorf("credentials for the policy: %s", resp.Error)
	}
	var grants []*v1.Grant
	for _, o := range a.grants.List() {
		grants = append(grants, o.(*v1.Grant))
	}
	p, problems := policy.For(s, grants, resp.Injections)
	defer func() {
		for _, c := range p.Credentials {
			clear(c.Value)
		}
	}()
	if err := rt.SetPolicy(ctx, idOf(s), p); err != nil {
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
		var ch <-chan client.Event
		l, err := a.Client.List(ctx, "Silo", "")
		if err == nil {
			ch, err = a.Client.Watch(ctx, "Silo", "", l.Metadata.ResourceVersion)
		}
		if err == nil {
			for ev := range ch {
				if ev.Type != "DELETED" || a.ControlPlaneHeld() {
					continue // a delete from a control plane this worker doesn't trust removes nothing
				}
				o, _, err := v1.Decode(ev.Object)
				if err != nil {
					continue
				}
				m := o.GetObjectMeta()
				a.seenDeleted.Store(m.UID, struct{}{})
				e.Changed(engine.Key{Kind: "Silo", Namespace: m.Namespace, Name: m.Name})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
