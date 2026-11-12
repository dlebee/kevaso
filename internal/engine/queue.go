package engine

import (
	"sync"
	"time"

	"kevaso.com/core/internal/clock"
)

// Backoff is the per-key retry delay after failures: Base, doubling each time, at most Max.
type Backoff struct {
	Base time.Duration
	Max  time.Duration
}

// DefaultBackoff is what controllers get unless they ask otherwise.
var DefaultBackoff = Backoff{Base: 50 * time.Millisecond, Max: 5 * time.Minute}

// Delay is the wait before attempt number `failures` (1 = first retry).
func (b Backoff) Delay(failures int) time.Duration {
	d := b.Base
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= b.Max {
			return b.Max
		}
	}
	if d > b.Max {
		return b.Max
	}
	return d
}

// queue is a work queue with the Kubernetes workqueue's guarantees:
//   - a key is queued at most once (bursts of changes become one reconcile);
//   - a key is never handed to two workers at once; changes during processing re-queue it once after;
//   - delayed adds (backoff, requeue-after) go through the clock.
type queue struct {
	clock   clock.Clock
	backoff Backoff

	mu         sync.Mutex
	cond       *sync.Cond
	items      []Key        // FIFO of keys ready to process
	queued     map[Key]bool // in items
	processing map[Key]bool // handed out, not Done yet
	dirty      map[Key]bool // changed while processing: re-queue on Done
	failures   map[Key]int  // consecutive failures, for backoff
	timers     map[Key]clock.Timer
	shutdown   bool
}

func newQueue(c clock.Clock, b Backoff) *queue {
	q := &queue{
		clock: c, backoff: b,
		queued: map[Key]bool{}, processing: map[Key]bool{}, dirty: map[Key]bool{},
		failures: map[Key]int{}, timers: map[Key]clock.Timer{},
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// add queues a key now. A pending delayed add for it is cancelled: now is sooner.
func (q *queue) add(k Key) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.addLocked(k)
}

func (q *queue) addLocked(k Key) {
	if q.shutdown {
		return
	}
	if t, ok := q.timers[k]; ok {
		t.Stop()
		delete(q.timers, k)
	}
	if q.processing[k] {
		q.dirty[k] = true
		return
	}
	if q.queued[k] {
		return
	}
	q.queued[k] = true
	q.items = append(q.items, k)
	q.cond.Signal()
}

// addAfter queues a key once d has passed; an earlier pending delayed add wins.
func (q *queue) addAfter(k Key, d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.shutdown || q.queued[k] {
		return
	}
	if d <= 0 {
		q.addLocked(k)
		return
	}
	if _, ok := q.timers[k]; ok {
		return
	}
	q.timers[k] = q.clock.AfterFunc(d, func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		delete(q.timers, k)
		q.addLocked(k)
	})
}

// retry queues a key after its next backoff delay.
func (q *queue) retry(k Key) time.Duration {
	q.mu.Lock()
	q.failures[k]++
	d := q.backoff.Delay(q.failures[k])
	q.mu.Unlock()
	q.addAfter(k, d)
	return d
}

// forget resets a key's backoff after a success.
func (q *queue) forget(k Key) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.failures, k)
}

// get blocks until a key is ready, or returns ok=false once the queue is shut down and empty.
func (q *queue) get() (Key, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && !q.shutdown {
		q.cond.Wait()
	}
	if len(q.items) == 0 {
		return Key{}, false
	}
	k := q.items[0]
	q.items = q.items[1:]
	delete(q.queued, k)
	q.processing[k] = true
	return k, true
}

// done marks a key finished; if it changed meanwhile, it's queued again.
func (q *queue) done(k Key) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.processing, k)
	if q.dirty[k] {
		delete(q.dirty, k)
		q.addLocked(k)
	}
}

// shutDown wakes every worker; get returns ok=false once nothing is left.
func (q *queue) shutDown() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.shutdown = true
	for _, t := range q.timers {
		t.Stop()
	}
	q.timers = map[Key]clock.Timer{}
	q.items = nil
	q.queued = map[Key]bool{}
	q.cond.Broadcast()
}
