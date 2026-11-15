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
	mu    sync.Mutex
	start time.Time
	last  map[string]contact
}

type contact struct {
	stamp time.Time // the heartbeat value seen
	at    time.Time // when we saw it change, our clock
}

// NewContacts starts counting at now (this leader's start).
func NewContacts(now time.Time) *Contacts {
	return &Contacts{start: now, last: map[string]contact{}}
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
