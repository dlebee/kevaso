// Package clock lets code wait without depending on real time: production uses Real, tests use Fake
// and move time forward explicitly, so backoff and requeue tests are instant and deterministic.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock is the time source code depends on.
type Clock interface {
	Now() time.Time
	// AfterFunc runs f in its own goroutine once d has passed. Stop cancels it.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer can be cancelled.
type Timer interface {
	Stop() bool
}

// Real is the wall clock.
type Real struct{}

// Now implements Clock.
func (Real) Now() time.Time { return time.Now() }

// AfterFunc implements Clock.
func (Real) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// Fake is a clock that only moves when told to.
type Fake struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

// NewFake returns a fake clock set to t.
func NewFake(t time.Time) *Fake { return &Fake{now: t} }

type fakeTimer struct {
	c       *Fake
	at      time.Time
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

// Now implements Clock.
func (c *Fake) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc implements Clock. A timer due now or earlier fires on the next Step (even Step(0)).
func (c *Fake) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return t
}

// Step moves time forward by d and runs every timer that became due, in due order.
func (c *Fake) Step(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due, rest []*fakeTimer
	for _, t := range c.timers {
		switch {
		case t.stopped:
		case !t.at.After(c.now):
			due = append(due, t)
		default:
			rest = append(rest, t)
		}
	}
	c.timers = rest
	c.mu.Unlock()
	sort.SliceStable(due, func(i, j int) bool { return due[i].at.Before(due[j].at) })
	for _, t := range due {
		t.f()
	}
}

// Pending is how many timers are waiting (tests use it to know a backoff was scheduled).
func (c *Fake) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped {
			n++
		}
	}
	return n
}
