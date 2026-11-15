package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/sdk/kri"
)

// RunningCheckEvery is how often the work a reconcile does inside a running silo looks again,
// on the agent's clock, at whether the silo still runs (whileItRuns).
const RunningCheckEvery = 2 * time.Second

// errNoLongerRunning: the runtime says the silo no longer runs (a VMM killed, a container whose
// process exited) while something ran inside it.
var errNoLongerRunning = errors.New("it no longer runs")

// errLeftHere: the silo was deleted, or placed elsewhere, while something ran inside it.
var errLeftHere = errors.New("it was deleted or placed elsewhere")

// interruptible is the context of the work under way inside one silo (by its key).
type interruptible struct {
	uid string
	end context.CancelCauseFunc
}

// whileItRuns runs work, the reconcile of a silo its runtime says runs, under a context (inside)
// that ends as soon as the silo no longer runs (its runtime's Status, looked at every
// RunningCheckEvery) or is deleted or placed elsewhere (interrupt). Nothing done inside a silo
// may wait for ever (found on the machines: a VMM killed while the agent waited for its guest's
// SSH, and that reconcile never ended, so the silo was never restarted, its Ready kept saying
// Running, and its delete was never processed). Work ended that way is looked at again at once:
// the next reconcile sees what happened (Failed: restarted after its backoff; gone: removed).
func (a *Agent) whileItRuns(ctx context.Context, k engine.Key, rt kri.Runtime, s *v1.Silo, work func(inside context.Context) (engine.Result, error)) (engine.Result, error) {
	inside, end := context.WithCancelCause(ctx)
	defer end(nil)
	go a.watchRunning(inside, rt, s, end)
	res, err := work(inside)
	if why := context.Cause(inside); inside.Err() != nil && ctx.Err() == nil && errors.Is(why, errNoLongerRunning) {
		a.log("silo %s/%s: %v: what ran inside it ended (%v); looking again", s.Namespace, s.Name, why, err)
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	}
	return res, err
}

// whileHere runs work, the reconcile of s placed here, under a context that ends once s is
// deleted or placed elsewhere (interrupt: the informer's handler, the delete watch), so that a
// delete is processed whatever was under way (a pull, a create, a start, a reset, an init step,
// a command in it), at once rather than when that ends by itself.
func (a *Agent) whileHere(ctx context.Context, k engine.Key, s *v1.Silo, work func(ctx context.Context) (engine.Result, error)) (engine.Result, error) {
	here, end := context.WithCancelCause(ctx)
	defer end(nil)
	me := &interruptible{uid: s.UID, end: end}
	a.interrupts.Store(k, me)
	defer a.interrupts.CompareAndDelete(k, me)
	if cur, ok := a.silos.Get(s.Namespace, s.Name); !ok || a.leftHere(cur.(*v1.Silo), s.UID) {
		end(errLeftHere) // between the read of the cache and now
	}
	res, err := work(here)
	if why := context.Cause(here); here.Err() != nil && ctx.Err() == nil && errors.Is(why, errLeftHere) {
		a.log("silo %s/%s: %v: what was under way for it ended (%v); looking again", s.Namespace, s.Name, why, err)
		return engine.Result{RequeueAfter: time.Millisecond}, nil
	}
	return res, err
}

// watchRunning ends inside (end) once rt says s no longer runs. A Status that fails says nothing.
func (a *Agent) watchRunning(inside context.Context, rt kri.Runtime, s *v1.Silo, end context.CancelCauseFunc) {
	ticks := a.tick(inside, RunningCheckEvery)
	for {
		select {
		case <-inside.Done():
			return
		case <-ticks:
		}
		sctx, cancel := context.WithTimeout(inside, time.Minute)
		st, err := rt.Status(sctx, idOf(s))
		cancel()
		if err == nil && st.State != kri.Running {
			end(fmt.Errorf("%w here (%s)", errNoLongerRunning, st.State))
			return
		}
	}
}

// leftHere says whether cur, the cached silo of uid's name, says the silo uid no longer runs here:
// another silo of that name, deleting, or placed on another host.
func (a *Agent) leftHere(cur *v1.Silo, uid string) bool {
	return cur.UID != uid || cur.DeletionTimestamp != nil || cur.Status.Host != a.HostName
}

// interrupt ends the work under way inside the silo k (whileItRuns), if it is of the silo uid
// ("": whichever): it was deleted, or placed elsewhere.
func (a *Agent) interrupt(k engine.Key, uid string) {
	if v, ok := a.interrupts.Load(k); ok && (uid == "" || v.(*interruptible).uid == uid) {
		v.(*interruptible).end(errLeftHere)
	}
}
