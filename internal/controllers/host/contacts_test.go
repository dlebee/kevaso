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

// K-015: a silo's start claim is judged by when this control plane first saw it, on its own
// clock, and seeing a new one is a contact from the host that wrote it. A new leader (new
// Contacts) has seen none: each is fresh from its start.
func TestStartClaimsAreTimedWhenSeenAndAreContacts(t *testing.T) {
	start := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	c := NewContacts(start)
	stamp := start.Add(-24 * time.Hour)
	h := &v1.Host{}
	h.Name, h.Status.LastHeartbeat = "hv1", &stamp
	c.Observe(h, start)
	at := start.Add(time.Hour)
	if d := c.Silence("hv1", at); d != time.Hour {
		t.Fatalf("before any claim: %v", d)
	}
	if age := c.StartClaimAge("dev/one", "claim-1", at); age != 0 {
		t.Fatalf("a claim not seen yet: age %v, want 0 (fresh)", age)
	}
	if age := c.SawStartClaim("dev/one", "hv1", "claim-1", at); age != 0 {
		t.Fatalf("first sight: age %v", age)
	}
	if d := c.Silence("hv1", at.Add(10*time.Second)); d != 10*time.Second {
		t.Fatalf("a new claim is a contact: silence %v, want 10s", d)
	}
	// The same claim again later: older, and not another contact.
	if age := c.SawStartClaim("dev/one", "hv1", "claim-1", at.Add(20*time.Second)); age != 20*time.Second {
		t.Fatalf("seen again: age %v", age)
	}
	if d := c.Silence("hv1", at.Add(40*time.Second)); d != 40*time.Second {
		t.Fatalf("the same claim seen again counted as contact: silence %v", d)
	}
	// The same old heartbeat seen again doesn't take the contact back either.
	c.Observe(h, at.Add(41*time.Second))
	if d := c.Silence("hv1", at.Add(45*time.Second)); d != 45*time.Second {
		t.Fatalf("an old heartbeat after a claim: silence %v", d)
	}
	// A changed claim (the host claimed again): fresh, and a contact.
	if age := c.SawStartClaim("dev/one", "hv1", "claim-2", at.Add(50*time.Second)); age != 0 {
		t.Fatalf("a new claim: age %v", age)
	}
	if age := c.StartClaimAge("dev/one", "claim-2", at.Add(55*time.Second)); age != 5*time.Second {
		t.Fatalf("age %v", age)
	}
	if d := c.Silence("hv1", at.Add(55*time.Second)); d != 5*time.Second {
		t.Fatalf("silence %v", d)
	}
	// A claim that doesn't say who wrote it: timed, nobody's contact.
	c.SawStartClaim("dev/two", "", "claim-x", at.Add(56*time.Second))
	if d := c.Silence("hv1", at.Add(60*time.Second)); d != 10*time.Second {
		t.Fatalf("silence %v", d)
	}
	// Forgotten (the silo is gone): a claim under that name is new again.
	c.ForgetStartClaim("dev/one")
	if age := c.StartClaimAge("dev/one", "claim-2", at.Add(time.Hour)); age != 0 {
		t.Fatalf("forgotten: age %v", age)
	}
	// A new leader: nothing seen, so every claim is fresh from its start.
	next := NewContacts(at.Add(2 * time.Hour))
	if age := next.StartClaimAge("dev/one", "claim-2", at.Add(2*time.Hour+time.Minute)); age != 0 {
		t.Fatalf("a new leader: age %v", age)
	}
	var nilC *Contacts
	if nilC.SawStartClaim("dev/one", "hv1", "c", at) != 0 || nilC.StartClaimAge("dev/one", "c", at) != 0 {
		t.Fatal("nil contacts")
	}
	nilC.ForgetStartClaim("dev/one")
}
