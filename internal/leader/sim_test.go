package leader_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"kevaso.com/core/internal/leader"
)

// A simulation of the election over real time, with Decide as each candidate's whole mind:
// candidates' clocks run at different rates and offsets, rounds come at jittered times, writes
// take a while to land (a compare-and-swap judged when it lands), and candidates lose the store
// for a while. A candidate acts from the moment its acquire lands until it steps down, or its
// watchdog sees the renew deadline pass (up to RetryPeriod/2 late). Two candidates never act at
// the same real moment.
func TestPropertySimulatedElectionNeverTwoActing(t *testing.T) {
	o := leader.Options{Lease: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second}.WithDefaults()
	runs := 200
	if testing.Short() {
		runs = 25
	}
	const step = 50 * time.Millisecond
	terms := 0
	for seed := 0; seed < runs; seed++ {
		r := rand.New(rand.NewSource(int64(seed)))
		type write struct {
			at       time.Duration // real time it lands
			expected int64
			next     leader.Record
			start    time.Time // the candidate's clock when its round began
			acquire  bool
		}
		type cand struct {
			id         string
			rate       float64
			offset     time.Duration
			self       leader.Self
			seen       leader.Seen
			nextRound  time.Duration
			inflight   *write
			cutUntil   time.Duration
			actingFrom time.Duration // -1: not acting
		}
		var (
			exists bool
			rec    leader.Record
			rev    int64
		)
		var cs []*cand
		for i := range 3 {
			cs = append(cs, &cand{id: fmt.Sprintf("cp%d", i), rate: 1 + (r.Float64()-0.5)*0.01, offset: time.Duration(r.Intn(10000)) * time.Millisecond,
				nextRound: time.Duration(r.Intn(2000)) * time.Millisecond, actingFrom: -1})
		}
		clockOf := func(c *cand, real time.Duration) time.Time {
			return t0.Add(c.offset + time.Duration(float64(real)*c.rate))
		}
		acting := func(c *cand, real time.Duration) bool {
			if !c.self.Leading || c.actingFrom < 0 {
				return false
			}
			// The watchdog looks every RetryPeriod/2 (its own clock): it may act that much past
			// the deadline.
			return clockOf(c, real).Sub(c.self.RenewedAt) <= o.RenewDeadline+o.RetryPeriod/2
		}
		for real := time.Duration(0); real < 5*time.Minute; real += step {
			for _, c := range cs {
				if c.inflight != nil && real >= c.inflight.at {
					w := c.inflight
					c.inflight = nil
					ok := (w.expected == 0 && !exists) || (w.expected != 0 && exists && rev == w.expected)
					if ok {
						exists, rec, rev = true, w.next, rev+1
						c.seen = leader.Seen{Revision: rev, At: w.start}
						c.self.RenewedAt = w.start
						if w.acquire {
							c.self.Leading, c.actingFrom = true, real
							terms++
						}
					} else if c.self.Leading && leader.Lost(c.self, clockOf(c, real), o) {
						c.self.Leading, c.actingFrom = false, -1
					}
				}
				if !acting(c, real) && c.self.Leading { // the watchdog ended its term
					c.self.Leading, c.actingFrom = false, -1
				}
				if real < c.nextRound || c.inflight != nil {
					continue
				}
				c.nextRound = real + time.Duration(float64(o.RetryPeriod)/c.rate) + time.Duration(r.Intn(300))*time.Millisecond
				now := clockOf(c, real)
				if r.Intn(40) == 0 {
					c.cutUntil = real + time.Duration(r.Intn(30000))*time.Millisecond
				}
				if real < c.cutUntil {
					if leader.Lost(c.self, now, o) {
						c.self.Leading, c.actingFrom = false, -1
					}
					continue
				}
				c.self.ID = c.id
				d := leader.Decide(c.self, leader.View{Exists: exists, Record: rec, Revision: rev}, c.seen, now, o)
				c.seen = d.Seen
				switch d.Action {
				case leader.StepDown:
					c.self.Leading, c.actingFrom = false, -1
				case leader.Acquire, leader.Renew:
					lat := time.Duration(r.Intn(400)) * time.Millisecond
					if r.Intn(20) == 0 {
						lat = time.Duration(r.Intn(12000)) * time.Millisecond // a write stuck a long while
					}
					c.inflight = &write{at: real + lat, expected: d.Expected, next: d.Next, start: now, acquire: d.Action == leader.Acquire}
				}
			}
			var who []string
			for _, c := range cs {
				if acting(c, real) {
					who = append(who, c.id)
				}
			}
			if len(who) > 1 {
				t.Fatalf("seed %d: at %s %v act at once", seed, real, who)
			}
		}
	}
	if terms < 3*runs { // a first leader, and hand-overs when it's cut off
		t.Fatalf("only %d terms in %d runs: the simulation hardly elects anyone", terms, runs)
	}
	t.Logf("%d terms in %d runs", terms, runs)
}
