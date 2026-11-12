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
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/informer"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/policy"
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
	Clock    clock.Clock
	Log      func(format string, args ...any)
	// LastContact, if set, says when this host last reached the control plane. Past FenceAfter
	// without contact, the agent fences: it stops the silos the control plane may recreate
	// elsewhere (onHostLoss: Recreate) and starts nothing, so two copies never run.
	LastContact func() time.Time
	FenceAfter  time.Duration // default 30s, under the control plane's 40s host lease
	// GuestHelper is the kvo-guest binary copied into silos whose runtime has a broker channel
	// (kevasod itself: it runs as kvo-guest by that name). Empty: no helper.
	GuestHelper string
	// GuestCA is the host's egress CA, put in every silo's trust store with the helper.
	GuestCA []byte
	// Host runs commands on the host, for provider volumes (format once, mount); nil: this host
	// can't mount them. VolumesDir is where they go (default DefaultVolumesDir).
	Host       hostexec.Runner
	VolumesDir string

	silos    *informer.Informer
	secrets  *informer.Informer
	grants   *informer.Informer
	fenced   atomic.Bool
	broker   *Broker
	prepared sync.Map // silo uid → struct{}: the guest helper is in place for this agent's run
	engine   *engine.Engine
}

// DefaultFenceAfter is under the host lease (40s), so a cut-off host has stopped its Recreate silos
// before the control plane even considers it lost.
const DefaultFenceAfter = 30 * time.Second

func (a *Agent) fenceAfter() time.Duration {
	if a.FenceAfter > 0 {
		return a.FenceAfter
	}
	return DefaultFenceAfter
}

// cutOff reports whether the host has gone too long without reaching the control plane.
func (a *Agent) cutOff() bool {
	if a.LastContact == nil {
		return false
	}
	last := a.LastContact()
	return !last.IsZero() && a.Clock.Now().Sub(last) > a.fenceAfter()
}

// fence runs while the agent runs: on losing contact it stops Recreate silos; on getting it back
// it looks at every silo again (the ones recreated elsewhere get removed).
func (a *Agent) fence(ctx context.Context, e *engine.Engine) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		switch cut := a.cutOff(); {
		case cut && !a.fenced.Load():
			a.fenced.Store(true)
			a.log("no contact with the control plane for over %s: fencing (stopping silos with onHostLoss: Recreate)", a.fenceAfter())
			for _, rt := range a.Runtimes {
				ids, err := rt.List(ctx)
				if err != nil {
					continue
				}
				for _, id := range ids {
					o, ok := a.silos.Get(id.Namespace, id.Name)
					if ok && o.(*v1.Silo).Policy() == v1.OnHostLossWait {
						continue // Wait silos are never started elsewhere: keep them running
					}
					if err := rt.Stop(ctx, id); err != nil {
						a.log("fence %s: %v", id, err)
					}
				}
			}
		case !cut && a.fenced.Load():
			a.fenced.Store(false)
			a.log("contact with the control plane is back: unfencing")
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
	a.silos = informer.New(a.Client, "Silo")
	a.secrets, a.grants = informer.New(a.Client, "Secret"), informer.New(a.Client, "Grant")
	a.broker = &Broker{Client: a.Client, HostName: a.HostName, Log: a.Log}
	e := engine.New(a.Clock)
	a.engine = e
	e.OnError = func(_ string, k engine.Key, err error, retry time.Duration) {
		a.log("silo %s: %v (retry in %v)", k, err, retry)
	}
	e.Register(a, engine.Options{Workers: 4})
	a.silos.AddHandler(func(k informer.Key) { e.Changed(engine.Key{Kind: "Silo", Namespace: k.Namespace, Name: k.Name}) })
	go a.silos.Run(ctx)
	// Rotation fan-out: a secret or grant changing tells the guest helpers of the silos here that
	// receive it.
	for kind, inf := range map[string]*informer.Informer{"Secret": a.secrets, "Grant": a.grants} {
		inf.AddHandler(func(k informer.Key) { a.fanOut(kind, k.Namespace, k.Name) })
		go inf.Run(ctx)
	}
	go a.RunTunnel(ctx)
	go a.fence(ctx, e)
	go a.resync(ctx, e)
	go func() { // after the first sync, look for runtime silos the API no longer knows
		if a.silos.WaitSynced(ctx) {
			a.collectGarbage(ctx, e)
		}
	}()
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
		for _, o := range a.silos.List() {
			if s := o.(*v1.Silo); s.Status.Host == a.HostName {
				e.Changed(engine.Key{Kind: "Silo", Namespace: s.Namespace, Name: s.Name})
			}
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
			return engine.Result{}, a.unmountVolumes(ctx, s.UID, s)
		}
		return engine.Result{}, nil
	}
	if a.fenced.Load() && s.Policy() != v1.OnHostLossWait {
		return engine.Result{RequeueAfter: 5 * time.Second}, nil // cut off: start nothing that may run elsewhere
	}
	// An older silo with the same name (deleted and re-created) must not linger next to it.
	if err := a.removeEverywhere(ctx, k, s); err != nil {
		return engine.Result{}, err
	}
	rt, ok := a.Runtimes[s.Spec.Runtime]
	if !ok {
		return engine.Result{}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Phase = PhaseFailed
			setCond(st, "Ready", meta.ConditionFalse, "RuntimeMissing", "runtime "+s.Spec.Runtime+" isn't installed on "+a.HostName, s.Generation, a.now())
		})
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
	id := idOf(s)
	rs, err := rt.Status(ctx, id)
	if err != nil {
		return engine.Result{}, err
	}
	switch rs.State {
	case kri.Absent:
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
		if err := rt.Create(ctx, kri.Spec{ID: id, Image: s.Spec.Image, CPU: s.Spec.Resources.CPU, Memory: mem, DiskBytes: disk,
			Volumes: vols, Command: s.Spec.Command}); err != nil {
			_ = a.setStatus(ctx, s, func(st *v1.SiloStatus) {
				st.Phase = PhaseFailed
				setCond(st, "Ready", meta.ConditionFalse, "CreateFailed", err.Error(), s.Generation, a.now())
			})
			return engine.Result{}, err
		}
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	case kri.Created, kri.Stopped:
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
		return engine.Result{}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
			st.Phase = PhaseFailed
			setCond(st, "Ready", meta.ConditionFalse, "RuntimeFailed", rs.Message, s.Generation, a.now())
		})
	}

	// Running: the silo's policy (runtimes that enforce grants themselves), the broker channel and
	// the guest helper, then init steps, then Ready.
	if pr, ok := rt.(kri.Policied); ok {
		if err := a.applyPolicy(ctx, pr, s); err != nil {
			return engine.Result{}, err
		}
	}
	if br, ok := rt.(kri.Broker); ok {
		if err := a.broker.Ensure(ctx, br, id); err != nil {
			return engine.Result{}, fmt.Errorf("broker channel: %w", err)
		}
		if rt.Info().Capabilities.Isolation == "vm" { // containers get kvo-guest and the CA mounted in
			if err := a.prepareGuest(ctx, rt, s); err != nil {
				return engine.Result{}, err
			}
		}
	}
	if done, err := a.runInit(ctx, rt, s); err != nil || !done {
		return engine.Result{}, err
	}
	return engine.Result{}, a.setStatus(ctx, s, func(st *v1.SiloStatus) {
		st.Phase, st.Address = PhaseRunning, rs.Address
		setCond(st, "Ready", meta.ConditionTrue, "Running", "running on "+a.HostName, s.Generation, a.now())
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
	for attempt := 0; attempt < 5; attempt++ {
		var cur v1.Silo
		if err := a.Client.Get(ctx, "Silo", s.Namespace, s.Name, &cur); err != nil {
			return err
		}
		if cur.UID != s.UID {
			return nil // deleted and re-created: not the silo we were working on
		}
		before := fmt.Sprintf("%+v", cur.Status)
		mutate(&cur.Status)
		if fmt.Sprintf("%+v", cur.Status) == before {
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
			a.log("removing %s from %s", id, rt.Info().Name)
			if a.broker != nil {
				a.broker.Close(id.UID)
			}
			a.prepared.Delete(id.UID)
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

// fanOut notifies the local silos a changed secret or grant reaches.
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
		a.broker.Notify(s.Namespace, s.Name, name)
		if a.engine != nil { // runtimes that enforce grants themselves get the new policy
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
