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

// keepClaim keeps this host's start claim of s fresh while its start takes long (its init steps):
// written anew every ClaimRefreshEvery, each a new claim, so the control plane, which counts a
// claim from when it first sees it, sees one standing for as long as anything of s runs here
// before its main process. The context it returns ends when a renewal finds s placed elsewhere
// (or changed, or deleted), or when the fence stops s here; whatever of s runs under it then
// ends (a runtime stops an init step whose context ends). kept stops the renewals, waiting for one
// in flight, and says why the context ended, if it did (nil: it didn't).
//
// A renewal that fails for want of contact is only logged: the claim then lapses, and the control
// plane counts the host's silence from its last sight of it; a silo that asked to stop without the
// control plane is stopped here by the fence first (its Kill covers the init step), and no other
// silo is restarted elsewhere (§0.7).
func (a *Agent) keepClaim(ctx context.Context, s *v1.Silo) (context.Context, func() error) {
	cctx, cancel := context.WithCancelCause(ctx)
	var mu sync.Mutex // held while a renewal runs
	stopped := false
	var t clock.Timer
	var tick func()
	tick = func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		if a.mustStop(s) {
			a.log("%s/%s: no contact with the control plane for over its after: ending its start here", s.Namespace, s.Name)
			cancel(errFenced)
			return
		}
		switch err := a.renewClaim(cctx, s); {
		case errors.Is(err, errPlacedElsewhere):
			a.log("%s/%s: renewing its start claim found it placed elsewhere or changed: ending its init steps here", s.Namespace, s.Name)
			cancel(errPlacedElsewhere)
			return
		case err != nil && cctx.Err() == nil:
			a.log("%s/%s: renewing its start claim: %v (trying again)", s.Namespace, s.Name, err)
		}
		t = a.Clock.AfterFunc(a.claimRefresh(), tick)
	}
	mu.Lock()
	t = a.Clock.AfterFunc(a.claimRefresh(), tick)
	mu.Unlock()
	var once sync.Once
	var why error
	return cctx, func() error {
		once.Do(func() {
			if cctx.Err() != nil {
				why = context.Cause(cctx)
			}
			mu.Lock()
			stopped = true
			t.Stop()
			mu.Unlock()
			if why == nil && cctx.Err() != nil {
				why = context.Cause(cctx) // ended while a renewal ran
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
	return true, rt.Stop(ctx, idOf(s))
}

func (a *Agent) claimRefresh() time.Duration {
	if a.ClaimRefresh > 0 {
		return a.ClaimRefresh
	}
	return ClaimRefreshEvery
}
