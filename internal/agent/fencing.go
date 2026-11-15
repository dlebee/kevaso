package agent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/sdk/kri"
)

// fencing is the agent's own fence across its passes (K-094):
//
//   - a silo is counted stopped only when its runtime's Status answers, after the kill, that
//     nothing of it runs; an error, or no answer in time, is not "stopped";
//   - it looks again on every pass, at every silo it must stop: one that runs again (a start in
//     flight, a runtime that brings it back by itself) is killed again;
//   - every runtime call has a timeout, and each silo's kill runs on its own: a hung engine
//     stalls only its own silos (a call that ignores its context is left to finish, and its silo
//     isn't tried again until it does);
//   - a silo it couldn't confirm stopped is logged loudly on every try and named on the Host
//     (ConditionFenceUnconfirmed) once contact is back: two copies may have run.
type fencing struct {
	a           *Agent
	mu          sync.Mutex
	inflight    map[string]time.Time // silo UID → since when its kill or check runs (a hung engine)
	unconfirmed map[string]string    // silo UID → what it is and why, in this outage
	confirmed   map[string]bool      // silo UID → confirmed stopped in this outage (logged once)
}

type fenceTarget struct {
	rt      kri.Runtime
	runtime string
	id      kri.ID
	after   time.Duration
}

// targets are the silos to stop now: every one a runtime here has, or the cache places here,
// that asked to stop and has been without contact longer than its after. Listing a runtime has a
// timeout too.
func (f *fencing) targets(ctx context.Context) []fenceTarget {
	a := f.a
	seen := map[string]bool{}
	var out []fenceTarget
	add := func(name string, rt kri.Runtime, id kri.ID) {
		if seen[id.UID] {
			return
		}
		o, ok := a.silos.Get(id.Namespace, id.Name)
		if !ok {
			return
		}
		s := o.(*v1.Silo)
		if s.UID != id.UID || !a.mustStop(s) {
			return
		}
		seen[id.UID] = true
		_, after := a.stopsOnLoss(s)
		out = append(out, fenceTarget{rt: rt, runtime: name, id: id, after: after})
	}
	for name, rt := range a.Runtimes {
		lctx, cancel := context.WithTimeout(ctx, fence.KillWithin)
		ids, err := rt.List(lctx)
		cancel()
		if err != nil {
			a.log("fence: listing %s: %v (its silos the API places here are still stopped)", name, err)
		}
		for _, id := range ids {
			add(name, rt, id)
		}
	}
	// A silo the API places here whose runtime couldn't list it (or lost its state) is still
	// stopped: kills find a silo by its name.
	for _, o := range a.silos.List() {
		s := o.(*v1.Silo)
		if rt, ok := a.Runtimes[s.Spec.Runtime]; ok && s.Status.Host == a.HostName {
			add(s.Spec.Runtime, rt, idOf(s))
		}
	}
	return out
}

// pass stops, and confirms stopped, every silo that must stop now. It waits for none of them:
// each silo's kill runs on its own, so the next pass, a second later, looks again at every other
// silo whatever one hung engine does.
func (f *fencing) pass(ctx context.Context) {
	ts := f.targets(ctx)
	if len(ts) == 0 {
		return
	}
	f.a.fenced.Store(true)
	for _, t := range ts {
		f.mu.Lock()
		since, busy := f.inflight[t.id.UID]
		if !busy {
			f.inflight[t.id.UID] = time.Now()
		}
		f.mu.Unlock()
		if busy {
			if time.Since(since) > 2*fence.KillWithin {
				f.unconfirm(t, "its kill or check hasn't returned for "+time.Since(since).Round(time.Second).String()+" (the engine hangs)")
			}
			continue
		}
		go func() {
			defer func() {
				f.mu.Lock()
				delete(f.inflight, t.id.UID)
				f.mu.Unlock()
			}()
			f.stop(ctx, t)
		}()
	}
}

// stop is one silo's fence in this pass: a look, a kill unless it is confirmed stopped already,
// a look again.
func (f *fencing) stop(ctx context.Context, t fenceTarget) {
	runs := func() (bool, error) {
		sctx, cancel := context.WithTimeout(ctx, fence.KillWithin)
		defer cancel()
		st, err := t.rt.Status(sctx, t.id)
		if err != nil {
			return true, err // can't say: not stopped
		}
		return st.State == kri.Running, nil
	}
	f.mu.Lock()
	was := f.confirmed[t.id.UID]
	f.mu.Unlock()
	if was {
		if r, err := runs(); err == nil && !r {
			return // still stopped
		}
		f.a.log("fence: %s runs again (or can't be seen) without the control plane: killing it again", t.id)
	} else {
		f.a.log("no contact with the control plane for over %s: stopping %s (onControlPlaneLoss: Stop, after %s)", t.after, t.id, t.after)
	}
	if f.a.silence() <= t.after {
		return // contact came back meanwhile: it may run again
	}
	kctx, cancel := context.WithTimeout(ctx, fence.KillWithin)
	// Killed, not stopped gracefully: it asked not to run on without the control plane.
	f.a.stoppedByUs(t.id.UID)
	err := kri.Kill(kctx, t.rt, t.id)
	cancel()
	if errors.Is(err, kri.ErrNotFound) {
		err = nil // not on this host: Status says whether anything of it runs
	}
	if err == nil {
		var r bool
		if r, err = runs(); err == nil && r {
			err = errors.New("it still runs after the kill")
		}
	}
	if err != nil {
		f.unconfirm(t, err.Error())
		return
	}
	f.mu.Lock()
	if f.confirmed == nil {
		f.confirmed = map[string]bool{}
	}
	f.confirmed[t.id.UID] = true
	delete(f.unconfirmed, t.id.UID)
	f.mu.Unlock()
	if _, was := f.a.fenceFaulted.LoadAndDelete(t.id.UID); was {
		f.a.log("fence: %s confirmed stopped by a kill here: armed again", t.id)
		f.a.resyncAll()
	}
}

func (f *fencing) unconfirm(t fenceTarget, why string) {
	f.a.log("FENCE FAULT: %s (%s) must stop and isn't confirmed stopped: %s. Trying again every %s; if the control plane restarts it elsewhere, two copies run",
		t.id, t.runtime, why, fence.CheckEvery)
	f.mu.Lock()
	f.unconfirmed[t.id.UID] = t.id.String() + " (" + t.runtime + "): " + why
	delete(f.confirmed, t.id.UID)
	f.mu.Unlock()
	f.a.fenceFaulted.Store(t.id.UID, why) // disarmed once contact is back (armFence)
}

// endOutage forgets this outage and returns what it couldn't confirm stopped, by silo.
func (f *fencing) endOutage() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, v := range f.unconfirmed {
		out = append(out, v)
	}
	sort.Strings(out)
	f.unconfirmed, f.confirmed = map[string]string{}, map[string]bool{}
	return out
}

// reportUnconfirmed says on the Host, when an outage ends, which silos this host's fence couldn't
// confirm stopped (True), or that it confirmed every one (False).
func (a *Agent) reportUnconfirmed(ctx context.Context, unconfirmed []string) {
	cond := meta.Condition{Type: ConditionFenceUnconfirmed, Status: meta.ConditionFalse, Reason: "AllStopped",
		Message: "the last outage's fence confirmed every silo it had to stop stopped"}
	if len(unconfirmed) > 0 {
		cond.Status, cond.Reason = meta.ConditionTrue, "NotConfirmed"
		cond.Message = "during the last outage this host's fence couldn't confirm these silos stopped: " + strings.Join(unconfirmed, "; ") +
			". If the control plane restarted them elsewhere, two copies may have run: check each one's other host and its data. " +
			"Each is disarmed (FenceArmed False, KillFailed) until a kill of it here is confirmed; the host is not rebooted for it."
		a.log("FENCE FAULT reported: %s", cond.Message)
	}
	for range 5 {
		var h v1.Host
		if err := a.Client.Get(ctx, "Host", "", a.HostName, &h); err != nil {
			return
		}
		meta.SetCondition(&h.Status.Conditions, cond, a.now().UTC().Truncate(time.Second))
		if err := a.Client.UpdateStatus(ctx, &h); err == nil {
			return
		}
	}
}
