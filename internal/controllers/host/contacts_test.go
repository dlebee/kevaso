package host

import (
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// K-014: how long a host has been silent is measured on the control plane's own clock, from when
// it last saw that host's heartbeat change: never by comparing the agent's timestamp with ours.
func TestContactsMeasureSilenceOnTheControlPlanesClock(t *testing.T) {
	start := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	c := NewContacts(start)
	beat := func(name string, stamp time.Time) *v1.Host {
		h := &v1.Host{}
		h.Name = name
		h.Status.LastHeartbeat = &stamp
		return h
	}
	// Never seen: silent since this control plane started (a new leader knows nothing earlier).
	if d := c.Silence("hv1", start.Add(time.Minute)); d != time.Minute {
		t.Fatalf("never seen: %v", d)
	}
	// The agent's clock is a day off, either way: it doesn't matter, only that it changed.
	c.Observe(beat("hv1", start.Add(-24*time.Hour)), start.Add(10*time.Second))
	if d := c.Silence("hv1", start.Add(70*time.Second)); d != time.Minute {
		t.Fatalf("after a beat at +10s, at +70s: %v", d)
	}
	// The same stamp again (another writer touched the Host): not a contact.
	c.Observe(beat("hv1", start.Add(-24*time.Hour)), start.Add(60*time.Second))
	if d := c.Silence("hv1", start.Add(70*time.Second)); d != time.Minute {
		t.Fatalf("a write without a new heartbeat counted as contact: %v", d)
	}
	c.Observe(beat("hv1", start.Add(24*time.Hour)), start.Add(65*time.Second))
	if d := c.Silence("hv1", start.Add(70*time.Second)); d != 5*time.Second {
		t.Fatalf("a new beat at +65s: %v", d)
	}
	// A host with no heartbeat yet: first sight is not a contact.
	c.Observe(&v1.Host{}, start.Add(65*time.Second))
	var nilC *Contacts
	if d := nilC.Silence("hv1", start); d != 0 {
		t.Fatalf("no contacts kept: %v (must never look silent)", d)
	}
}
