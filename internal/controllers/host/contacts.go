package host

import (
	"sync"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Contacts is how long each host has been silent, by this control plane's own clock (audit K-014,
// brainstorm §0.7). A host's heartbeat stamp is the agent's clock: it is used only to see that a
// new heartbeat arrived, never compared with ours. Kept in memory by the leader: a new leader
// knows nothing earlier than its own start, so it counts silence from then (later, never sooner).
type Contacts struct {
	mu     sync.Mutex
	start  time.Time
	last   map[string]contact
	claims map[string]claimSeen // by silo (namespace/name)
}

// claimSeen is a silo's start claim as this control plane first saw it (K-015).
type claimSeen struct {
	id string    // the claim as written: a new or changed claim is another id
	at time.Time // when we first saw it, our clock
}

type contact struct {
	stamp time.Time // the heartbeat value seen
	at    time.Time // when we saw it change, our clock
}

// NewContacts starts counting at now (this leader's start).
func NewContacts(now time.Time) *Contacts {
	return &Contacts{start: now, last: map[string]contact{}, claims: map[string]claimSeen{}}
}

// HeartbeatStamp is the lastHeartbeat a heartbeat writes over stored: now, to the nanosecond, and
// never stored itself (K-106). The stamp changing is the only sign on a Host that a heartbeat
// landed (Observe), so a heartbeat whose write stored the same stamp again was a contact to the
// host that sent it and none to the control plane: a worker's clock one period behind did that on
// every other beat, and two beats within one second did it too. Not max(now, stored+δ): a stamp
// a fast clock left in the future is replaced at the next beat, not kept.
func HeartbeatStamp(stored *time.Time, now time.Time) *time.Time {
	t := now.UTC().Round(0)
	if stored != nil && t.Equal(*stored) {
		t = t.Add(time.Nanosecond)
	}
	return &t
}

// Observe records that h was seen at now: a heartbeat stamp different from the last one seen is a
// contact, counted from now on this control plane's clock. The stamp is only told apart from the
// last one, never compared with our clock; every heartbeat that lands stores a new one
// (HeartbeatStamp), so every one is a contact. Seeing only the latest of several versions is the
// same contact, a little later (later is the safe side: less silence). Call it for every version
// of every Host as it is seen.
func (c *Contacts) Observe(h *v1.Host, now time.Time) {
	if c == nil || h.Status.LastHeartbeat == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.last[h.Name]; ok && prev.stamp.Equal(*h.Status.LastHeartbeat) {
		return
	}
	c.last[h.Name] = contact{stamp: *h.Status.LastHeartbeat, at: now}
}

// Silence is how long since this control plane last saw a heartbeat of host, or since it started
// counting if it saw none. Nil Contacts: 0 (nothing known: never silent enough to act on).
func (c *Contacts) Silence(host string, now time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	from := c.start
	if l, ok := c.last[host]; ok {
		from = l.at
	}
	return max(now.Sub(from), 0)
}

// SawStartClaim records that silo carries the start claim id, written by host (K-015), and returns
// how long ago this control plane first saw that very claim, on its own clock: the claim's own
// timestamp is the agent's clock and is never compared with ours. A claim not seen before, or
// changed, is seen now, and is a contact from host (it just wrote; Silence counts from now). A
// new leader sees every claim for the first time at its start: each is fresh for a full window
// from then. Call it for every version of every silo as it is seen.
func (c *Contacts) SawStartClaim(silo, host, id string, now time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.claims[silo]; ok && prev.id == id {
		return max(now.Sub(prev.at), 0)
	}
	c.claims[silo] = claimSeen{id: id, at: now}
	if host == "" {
		return 0 // a claim that doesn't say who wrote it: fresh, but nobody's contact
	}
	l := c.last[host]
	l.at = now // the heartbeat stamp stays: only a new one is a heartbeat
	c.last[host] = l
	return 0
}

// StartClaimAge is how long ago this control plane first saw silo's start claim id: 0 when it
// hasn't seen that claim yet (a claim not seen is as fresh as can be). Nil Contacts: 0.
func (c *Contacts) StartClaimAge(silo, id string, now time.Time) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.claims[silo]; ok && prev.id == id {
		return max(now.Sub(prev.at), 0)
	}
	return 0
}

// ForgetStartClaim drops what is kept of a silo that is gone.
func (c *Contacts) ForgetStartClaim(silo string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.claims, silo)
}

// ReasonWorkerHeld is the reason of the Ready condition a heartbeat sends while its worker is held
// (§0.7: it judged its control plane older than what it saw, or can't judge it): this beat is not
// its fence's contact (K-108). The worker says it in the beat itself, so the control plane counts
// exactly the beats the worker didn't, and a worker that never says it is counted as before.
const ReasonWorkerHeld = "WorkerHeld"

// HeldBeat reports whether a heartbeat's Host status, as sent, says its worker is held (K-108):
// its Ready condition's reason is ReasonWorkerHeld.
func HeldBeat(st v1.HostStatus) bool {
	r := meta.FindCondition(st.Conditions, "Ready")
	return r != nil && r.Reason == ReasonWorkerHeld
}

// Beat makes next, a heartbeat's Host status over stored, what the control plane keeps, and says
// whether it is a contact. A held worker's (HeldBeat) is none (K-108): its stamp and its Ready
// condition stay as stored, so the host is counted silent and marked lost as one out of contact,
// as its fence counts it. Any other is a contact, stamped by HeartbeatStamp.
func Beat(stored v1.HostStatus, next *v1.HostStatus, now time.Time) bool {
	if !HeldBeat(*next) {
		next.LastHeartbeat = HeartbeatStamp(stored.LastHeartbeat, now)
		return true
	}
	next.LastHeartbeat = stored.LastHeartbeat
	conds := make([]meta.Condition, 0, len(next.Conditions))
	for _, c := range next.Conditions {
		if c.Type != "Ready" {
			conds = append(conds, c)
		}
	}
	if r := meta.FindCondition(stored.Conditions, "Ready"); r != nil {
		conds = append(conds, *r)
	}
	next.Conditions = conds
	return false
}
