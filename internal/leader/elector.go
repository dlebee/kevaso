package leader

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

// Kind is the store kind leases are kept under (design §4.1: "Lease objects for leader election").
// They live in the store directly, like join tokens: the API doesn't serve them.
const Kind = "Lease"

// ControllersKey is the lease of the controllers and the scheduler.
var ControllersKey = store.Key{Kind: Kind, Name: "kevaso-controllers"}

// Elector runs one candidate.
type Elector struct {
	Store   store.Store
	Key     store.Key
	ID      string // this candidate: the host's name
	Clock   clock.Clock
	Options Options
	Log     func(format string, args ...any)

	mu     sync.Mutex
	self   Self
	seen   Seen
	term   int64
	cancel context.CancelFunc // ends the current term's work
	done   chan struct{}      // closed when that work returned
}

// Leading reports whether this candidate acts as the leader now, and in which term.
// A leader past its renew deadline isn't, even before its next round notices.
func (e *Elector) Leading() (bool, int64) {
	o := e.Options.WithDefaults()
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.self.Leading && !Lost(e.self, e.Clock.Now(), o), e.term
}

// Run takes part in the election until ctx ends: lead runs, with a context that ends when the term
// does, each time this candidate wins. When ctx ends, a lease still held is released, so another
// candidate takes over at once instead of after a whole Lease.
func (e *Elector) Run(ctx context.Context, lead func(ctx context.Context)) {
	o := e.Options.WithDefaults()
	for {
		e.Step(ctx, lead)
		select {
		case <-ctx.Done():
			e.stop()
			rctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			e.release(rctx)
			cancel()
			return
		case <-time.After(o.RetryPeriod):
		}
	}
}

// Step is one round: read the lease, decide, write. It starts or stops lead as the round decides.
func (e *Elector) Step(ctx context.Context, lead func(ctx context.Context)) Decision {
	o := e.Options.WithDefaults()
	now := e.Clock.Now()
	var v View
	obj, err := e.Store.Get(ctx, e.Key)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		e.mu.Lock()
		lost := Lost(e.self, now, o)
		e.mu.Unlock()
		if lost {
			e.logf("leader election: %v; stepping down", err)
			e.stop()
			return Decision{Action: StepDown, Reason: err.Error()}
		}
		return Decision{Action: Follow, Reason: err.Error()}
	default:
		var r Record
		if jerr := json.Unmarshal(obj.Data, &r); jerr != nil {
			r = Record{} // unreadable: treat as released (a takeover is a new term anyway)
		}
		v = View{Exists: true, Record: r, Revision: obj.Revision}
	}
	e.mu.Lock()
	e.self.ID = e.ID
	d := Decide(e.self, v, e.seen, now, o)
	e.seen = d.Seen
	e.mu.Unlock()

	switch d.Action {
	case StepDown:
		e.logf("leader election: %s; stepping down", d.Reason)
		e.stop()
	case Acquire, Renew:
		if d.Action == Acquire {
			d.Next.Since = now.UTC().Format(time.RFC3339)
		}
		data, _ := json.Marshal(d.Next)
		var werr error
		var wrote store.Object
		if d.Expected == 0 {
			wrote, werr = e.Store.Create(ctx, e.Key, data)
		} else {
			wrote, werr = e.Store.Update(ctx, e.Key, data, d.Expected)
		}
		if werr != nil {
			// Someone else wrote first (conflict, exists), or the store is away: not ours this round.
			e.mu.Lock()
			lost := Lost(e.self, e.Clock.Now(), o)
			e.mu.Unlock()
			if d.Action == Renew && !lost {
				return Decision{Action: Follow, Reason: "renew failed: " + werr.Error()}
			}
			if d.Action == Renew {
				e.logf("leader election: renew failed (%v); stepping down", werr)
				e.stop()
				return Decision{Action: StepDown, Reason: werr.Error()}
			}
			return Decision{Action: Follow, Reason: "acquire lost: " + werr.Error()}
		}
		e.mu.Lock()
		e.seen = Seen{Revision: wrote.Revision, At: now}
		e.self.RenewedAt = now // when the write started: the safe side
		starting := d.Action == Acquire
		if starting {
			e.self.Leading, e.term = true, d.Next.Term
		}
		e.mu.Unlock()
		if starting {
			e.logf("leader election: %s leads (term %d): %s", e.ID, d.Next.Term, d.Reason)
			e.start(ctx, lead)
		}
	}
	return d
}

func (e *Elector) start(ctx context.Context, lead func(ctx context.Context)) {
	e.mu.Lock()
	if e.cancel != nil { // a term still winding down (shouldn't be: Acquire comes only when not leading)
		e.mu.Unlock()
		e.stop()
		e.mu.Lock()
	}
	tctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	e.cancel, e.done = cancel, done
	e.mu.Unlock()
	go func() {
		defer close(done)
		if lead != nil {
			lead(tctx)
		}
	}()
	go e.watchdog(tctx, cancel)
}

// watchdog ends the term's work once the renew deadline passes, even while a round is stuck on a
// store that doesn't answer.
func (e *Elector) watchdog(ctx context.Context, cancel context.CancelFunc) {
	o := e.Options.WithDefaults()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(o.RetryPeriod / 2):
		}
		if ok, _ := e.Leading(); !ok {
			cancel()
			return
		}
	}
}

// stop ends the current term's work and waits for it.
func (e *Elector) stop() {
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	e.cancel, e.done = nil, nil
	e.self.Leading = false
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// release gives the lease up if it still names this candidate.
func (e *Elector) release(ctx context.Context) {
	obj, err := e.Store.Get(ctx, e.Key)
	if err != nil {
		return
	}
	var r Record
	if json.Unmarshal(obj.Data, &r) != nil || r.Holder != e.ID {
		return
	}
	r.Holder = ""
	data, _ := json.Marshal(r)
	_, _ = e.Store.Update(ctx, e.Key, data, obj.Revision)
}

func (e *Elector) logf(f string, a ...any) {
	if e.Log != nil {
		e.Log(f, a...)
	}
}
