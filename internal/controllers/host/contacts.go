package host

import (
	"sync"
	"time"

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

// Observe records that h was seen at now: a heartbeat stamp different from the last one seen is a
// contact. Call it for every version of every Host as it is seen.
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
