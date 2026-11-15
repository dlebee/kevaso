package agent

import (
	"context"
	"errors"
	"sync"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// What may happen on a host before its start claim of a silo applied (K-088), and why it's
// harmless: nothing of the silo's own code runs, and none of its secrets reach the host.
//
//   - Status writes (Creating, NotRunning, Moving): each is refused on a silo the store places
//     elsewhere (writeStatus).
//   - The fence record (recordForFence): it only makes the fence able to stop the silo here.
//   - Provider and root-disk volumes mounted on the host (mountVolumes, mountRootDisk): storage,
//     no program of the silo's; the control plane attached them to this host.
//   - The image pulled, and Create: a VM's disk, cloud-init seed, TAP and VMM unit (not started);
//     a container's address, files, engine volumes and its pause container. The pause container
//     runs kevasod's own pause program, nothing of the silo's: no image of its, no volume, no
//     secret, all capabilities dropped, read-only, with only the silo's network namespace wired
//     to this host's bridge (an address on this host's bridge, from this host's pool).
//
// After the claim, and only then: the secrets delivered to the host (HostSecrets), the init
// containers, and the main process. A VM's and an OpenShell sandbox's init steps run inside it
// through Exec, after its start, so after its claim.

// errFenced: the fence stops the silo here (no contact for longer than its after): whatever of
// its start was under way ends.
var errFenced = errors.New("stopped by the fence: no contact with the control plane")

// errClaimConflict: the claim's compare-and-swap lost to another write of the silo.
var errClaimConflict = errors.New("the silo changed since it was read")

// initRunner is a runtime that says whether one of a silo's init steps runs now (the container
// runtimes: its init container; the strict fake).
type initRunner interface {
	InitRunning(ctx context.Context, id kri.ID) (bool, error)
}

// claimKeeper keeps this host's start claim of one silo fresh, across reconciles, for as long as
// its start runs here: from just after its first claim applied (before any of its code runs or it
// gets its secrets) until it is reported Running here, or its start ended and nothing of it runs
// (review of K-088): the init containers, the runtime's Start however long it takes, and a VM's or
// an OpenShell sandbox's init steps run through Exec. It writes the claim anew every
// ClaimRefreshEvery, each a new claim, so the control plane, which counts a claim from when it
// first sees it, sees one standing for as long as the start runs.
//
// Its context ends when a renewal finds s placed elsewhere (or changed, or deleted), or when the
// fence stops s here; whatever of s's start runs under it then ends (a runtime stops an init step,
// a Start, an Exec whose context ends).
//
// A renewal that fails for want of contact is only logged: the claim then lapses, and the control
// plane counts the host's silence from its last sight of it; a silo that asked to stop without the
// control plane is stopped here by the fence first (its Kill covers the init step), and no other
// silo is restarted elsewhere (§0.7).
type claimKeeper struct {
	a       *Agent
	s       *v1.Silo // as it was claimed (its UID and generation)
	ctx     context.Context
	cancel  context.CancelCauseFunc
	mu      sync.Mutex // held while a renewal, or a claim through claimNow, runs
	stopped bool
	t       clock.Timer
}

// errClaimEnded: a keeper's renewals ended (the silo is reported Running, or its start ended).
var errClaimEnded = errors.New("its start claim is no longer kept")

// keepClaim starts keeping s's start claim fresh, just after a claim of it applied (claimStart).
// A keeper s had already is replaced.
func (a *Agent) keepClaim(s *v1.Silo) *claimKeeper {
	base := a.runCtx
	if base == nil {
		base = context.Background()
	}
	a.reported.Delete(s.UID) // a start here again
	k := &claimKeeper{a: a, s: s}
	k.ctx, k.cancel = context.WithCancelCause(base)
	k.mu.Lock()
	k.t = a.Clock.AfterFunc(a.claimRefresh(), k.tick)
	k.mu.Unlock()
	if old, loaded := a.claims.Swap(s.UID, k); loaded {
		old.(*claimKeeper).stop()
	}
	return k
}

// claimKept is the keeper of s's claim that still renews it (the same generation), or nil.
func (a *Agent) claimKept(s *v1.Silo) *claimKeeper {
	v, ok := a.claims.Load(s.UID)
	if !ok {
		return nil
	}
	k := v.(*claimKeeper)
	if k.s.Generation != s.Generation || k.ctx.Err() != nil {
		return nil
	}
	return k
}

// reportedRunning says whether this run reported s Running at its generation since its last start
// here: a cache that still says otherwise is behind that write, and nothing starts again.
func (a *Agent) reportedRunning(s *v1.Silo) bool {
	g, ok := a.reported.Load(s.UID)
	return ok && g.(int64) == s.Generation
}

// endStart ends a start of the silo uid under way here (its init step, its Start): its claim's
// context ends as when a renewal finds it placed elsewhere.
func (a *Agent) endStart(uid string) {
	if v, ok := a.claims.Load(uid); ok {
		v.(*claimKeeper).cancel(errPlacedElsewhere)
	}
}

// endClaim stops renewing s's claim (reported Running, or its start ended and nothing of it runs).
func (a *Agent) endClaim(uid string) {
	if v, ok := a.claims.LoadAndDelete(uid); ok {
		v.(*claimKeeper).stop()
	}
}

// settleClaim ends s's claim after a start that didn't get to Running in this reconcile, once
// nothing of it runs here: one whose renewals ended (placed elsewhere, the fence), or one rt says
// doesn't run. While something of it may run, the claim is kept fresh.
func (a *Agent) settleClaim(ctx context.Context, rt kri.Runtime, s *v1.Silo) {
	v, ok := a.claims.Load(s.UID)
	if !ok {
		return
	}
	if v.(*claimKeeper).ctx.Err() != nil {
		a.endClaim(s.UID)
		return
	}
	if st, err := rt.Status(ctx, idOf(s)); err == nil && st.State != kri.Running {
		a.endClaim(s.UID)
	}
}

func (k *claimKeeper) tick() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.stopped || k.ctx.Err() != nil {
		return
	}
	a, s := k.a, k.s
	if a.mustStop(s) {
		a.log("%s/%s: no contact with the control plane for over its after: ending its start here", s.Namespace, s.Name)
		k.cancel(errFenced)
		return
	}
	switch err := a.renewClaim(k.ctx, s); {
	case unknownNow(err):
		// The store doesn't have it (or has another of that name): its start ends. Not a delete
		// seen here (errUnknown): what of it runs is stopped, and its copy kept unless the delete
		// watch saw its delete.
		a.log("%s/%s: renewing its start claim found the control plane doesn't know it (%v): ending its start here (its disk and volumes are kept unless its delete is seen)", s.Namespace, s.Name, err)
		k.cancel(errUnknown)
		return
	case errors.Is(err, errPlacedElsewhere):
		a.log("%s/%s: renewing its start claim found it placed elsewhere or changed: ending its start here", s.Namespace, s.Name)
		k.cancel(errPlacedElsewhere)
		return
	case err != nil && k.ctx.Err() == nil:
		a.log("%s/%s: renewing its start claim: %v (trying again)", s.Namespace, s.Name, err)
	}
	if k.ctx.Err() == nil {
		k.t = a.Clock.AfterFunc(a.claimRefresh(), k.tick)
	}
}

// stop ends the renewals, waiting for one in flight.
func (k *claimKeeper) stop() {
	k.mu.Lock()
	k.stopped = true
	k.t.Stop()
	k.mu.Unlock()
	k.cancel(errClaimEnded)
}

// claimNow claims s once more (claimStart), with no renewal in flight: right before its main
// process starts, on what is stored at this moment. The next renewal is a refresh from now.
func (k *claimKeeper) claimNow(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ctx.Err() != nil {
		return context.Cause(k.ctx)
	}
	err := k.a.claimStart(ctx, k.s)
	if err == nil && !k.stopped {
		k.t.Stop()
		k.t = k.a.Clock.AfterFunc(k.a.claimRefresh(), k.tick)
	}
	return err
}

// within is ctx, ended too when the keeper's context ends. done detaches it and says why it
// ended, if it did (nil: it didn't); it may be called more than once.
func (k *claimKeeper) within(ctx context.Context) (context.Context, func() error) {
	cctx, cancel := context.WithCancelCause(ctx)
	detach := context.AfterFunc(k.ctx, func() { cancel(context.Cause(k.ctx)) })
	var once sync.Once
	var why error
	return cctx, func() error {
		once.Do(func() {
			detach()
			if cctx.Err() != nil {
				why = context.Cause(cctx)
			}
			cancel(nil)
		})
		return why
	}
}

// renewClaim writes this host's start claim of s anew: on what is stored now, each try a fresh
// read and a compare-and-swap, so a renewal never applies to a silo placed elsewhere.
func (a *Agent) renewClaim(ctx context.Context, s *v1.Silo) error {
	for range 5 {
		err := a.writeClaim(ctx, s)
		if !errors.Is(err, errClaimConflict) {
			return err
		}
	}
	return errors.New("the silo kept changing")
}

// startEnded is the end of a start this host claimed that didn't reach its main process: why the
// claim's context ended (placed elsewhere, the fence), else err.
func (a *Agent) startEnded(s *v1.Silo, why, err error) (engine.Result, error) {
	switch {
	case errors.Is(why, errPlacedElsewhere):
		return a.lostClaim(s, why)
	case errors.Is(why, errFenced):
		return engine.Result{RequeueAfter: 5 * time.Second}, nil
	case why != nil:
		return engine.Result{RequeueAfter: 2 * time.Second}, nil // the agent stops
	}
	return engine.Result{}, err
}

// stopOrphanInit stops an init step of s that runs while no start of this agent waits for it (one
// left by an earlier run of kevasod: its result can never be recorded, and it runs the silo's code
// unseen). The reconcile of s is the only one that runs its steps, one at a time, so an init step
// found running here isn't this run's. Stopped says it did; the steps run again from the start.
func (a *Agent) stopOrphanInit(ctx context.Context, rt kri.Runtime, s *v1.Silo, rs kri.Status) (stopped bool, err error) {
	ir, ok := rt.(initRunner)
	if !ok || rs.State != kri.Running {
		return false, nil
	}
	running, err := ir.InitRunning(ctx, idOf(s))
	if err != nil || !running {
		return false, err
	}
	a.log("%s/%s: an init step runs that no start here waits for (left by an earlier run): stopping it; its steps run again", s.Namespace, s.Name)
	a.stoppedByUs(s.UID)
	return true, rt.Stop(ctx, idOf(s))
}

func (a *Agent) claimRefresh() time.Duration {
	if a.ClaimRefresh > 0 {
		return a.ClaimRefresh
	}
	return ClaimRefreshEvery
}
