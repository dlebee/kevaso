// Package leader elects one control plane to run the controllers and the scheduler (design §4.1:
// any system node serves the API; one at a time acts). The lease is one record in the store, and
// every write to it is a compare-and-swap on the store's revision, so two candidates can never both
// win the same revision: whoever writes first holds it, the other gets a conflict and follows.
//
// Time never crosses machines. A candidate doesn't trust the holder's clock: it takes over only after
// it has seen the record's revision stay the same for a whole Lease on its own clock. The holder
// stops acting once RenewDeadline has passed on its own clock since it last started a renewal that
// went through. With RenewDeadline well under Lease, the old leader has stopped before anyone can
// start (clock rates differ by far less than Lease − RenewDeadline).
//
// Decide is the whole decision, pure; Elector reads and writes the store around it.
package leader

import (
	"time"
)

// Record is what the lease holds.
type Record struct {
	Holder string `json:"holder"`         // the candidate leading; "" once released
	Term   int64  `json:"term"`           // bumped at every change of holder
	Since  string `json:"since,omitzero"` // when this term began, the holder's clock (for people only)
}

// View is the lease as a candidate just read it.
type View struct {
	Exists   bool
	Record   Record
	Revision int64 // the store revision of the record's last write
}

// Seen is a candidate's memory of the lease: the last revision it saw change, and when (its clock).
type Seen struct {
	Revision int64
	At       time.Time
}

// Self is what a candidate knows about itself.
type Self struct {
	ID        string
	Leading   bool      // it is acting as the leader now
	RenewedAt time.Time // when it started its last write that went through
}

// Options are the election's timings.
type Options struct {
	Lease         time.Duration // silence before a takeover (default 15s)
	RenewDeadline time.Duration // a leader that couldn't renew this long stops (default 10s)
	RetryPeriod   time.Duration // how often candidates look (default 2s)
}

// WithDefaults fills unset timings and keeps RenewDeadline under Lease.
func (o Options) WithDefaults() Options {
	if o.Lease <= 0 {
		o.Lease = 15 * time.Second
	}
	if o.RenewDeadline <= 0 || o.RenewDeadline >= o.Lease {
		o.RenewDeadline = o.Lease * 2 / 3
	}
	if o.RetryPeriod <= 0 || o.RetryPeriod >= o.RenewDeadline {
		o.RetryPeriod = o.RenewDeadline / 5
	}
	return o
}

// Action is what a candidate does this round.
type Action string

const (
	Follow   Action = "Follow"   // someone else leads, or may still: wait
	Acquire  Action = "Acquire"  // take the lease (create it, or swap it at Expected)
	Renew    Action = "Renew"    // keep the lease: swap it at Expected
	StepDown Action = "StepDown" // stop acting now: the lease isn't ours any more, or may not be
)

// Decision is one round's decision.
type Decision struct {
	Action   Action
	Expected int64  // the revision to swap at (0 with Acquire: create the record)
	Next     Record // the record to write (Acquire, Renew)
	Seen     Seen   // the candidate's memory after this round
	Reason   string
}

// Decide is one round for candidate me, from the lease as read now and its memory of it.
func Decide(me Self, v View, seen Seen, now time.Time, o Options) Decision {
	o = o.WithDefaults()
	if !v.Exists {
		return Decision{Action: Acquire, Next: Record{Holder: me.ID, Term: 1}, Seen: seen, Reason: "no lease yet"}
	}
	if v.Revision != seen.Revision {
		seen = Seen{Revision: v.Revision, At: now}
	}
	r := v.Record
	if r.Holder == me.ID {
		if me.Leading && now.Sub(me.RenewedAt) > o.RenewDeadline {
			return Decision{Action: StepDown, Seen: seen, Reason: "couldn't renew within the deadline"}
		}
		if !me.Leading {
			// Ours on the record, but we aren't acting (we restarted, or stepped down): take it as a
			// new term, so anything the previous term did is clearly older.
			return Decision{Action: Acquire, Expected: v.Revision, Next: Record{Holder: me.ID, Term: r.Term + 1}, Seen: seen, Reason: "the lease names us; starting a new term"}
		}
		return Decision{Action: Renew, Expected: v.Revision, Next: r, Seen: seen, Reason: "renewing"}
	}
	if me.Leading {
		return Decision{Action: StepDown, Seen: seen, Reason: "the lease is " + holderName(r.Holder) + "'s now"}
	}
	if r.Holder == "" {
		return Decision{Action: Acquire, Expected: v.Revision, Next: Record{Holder: me.ID, Term: r.Term + 1}, Seen: seen, Reason: "released"}
	}
	if seen.At.IsZero() || now.Sub(seen.At) < o.Lease {
		return Decision{Action: Follow, Seen: seen, Reason: r.Holder + " leads"}
	}
	return Decision{Action: Acquire, Expected: v.Revision, Next: Record{Holder: me.ID, Term: r.Term + 1}, Seen: seen,
		Reason: r.Holder + " hasn't renewed for " + o.Lease.String()}
}

// Lost is whether a leader that can't read the lease at all must stop now.
func Lost(me Self, now time.Time, o Options) bool {
	o = o.WithDefaults()
	return me.Leading && now.Sub(me.RenewedAt) > o.RenewDeadline
}

func holderName(h string) string {
	if h == "" {
		return "nobody"
	}
	return h
}
