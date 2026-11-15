package ingress_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/ingress"
)

// K-120: while the agent can't tell what the proxy serves (a hand edit, a proxy on a config
// that is no record's), one refused Ingress, even another namespace's that was never served,
// holds the class: nothing new goes out. The owner's decision: no automatic end, but an alert on
// the class at once. So the first pass says, in what it returns for the class's status, that the
// class is held because what is served is unknown, which Ingresses hold it, that it does not end
// by itself and what ends it; and passes after any number of retries are still held, until a
// person fixes or removes the refused Ingress.
func TestK120AnUnknownHoldAlertsAtOnceAndDoesNotEndByItself(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			settle(t, r, want(many(6)...), m, nil, "", 1)
			// What the proxy runs is no longer what the agent applied.
			if r.name == "kong" {
				r.live = []byte(strings.Replace(string(r.live), "10.64.0.5", "10.64.0.9", 1))
			} else {
				cfg := configPath(t, r)
				r.px.Files[cfg] = []byte(strings.Replace(string(r.px.Files[cfg]), "10.64.0.5:81", "10.64.0.9:81", 1))
			}
			before := r.served()
			now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
			mem := &ingress.Memory{Now: func() time.Time { return now }}
			bad := route("other/bad", poison+"99.example.com", 99) // another namespace's, never served
			w := want(append(many(6), bad)...)
			res, _, _ := settle(t, r, w, mem, nil, "", 1)
			if res.Held == "" || res.Unknown == "" {
				t.Fatalf("first pass not held as unknown: held %q unknown %q left out %v", res.Held, res.Unknown, res.LeftOut)
			}
			for _, want := range []string{"can't tell what the proxy serves", "other/bad", "does not end by itself"} {
				if !strings.Contains(res.Held, want) {
					t.Errorf("the class's reason %q doesn't say %q", res.Held, want)
				}
			}
			for i := 0; i < 8; i++ { // past every retry of the backoff
				now = now.Add(ingress.RetryMax + time.Minute)
				res, _, _ = settle(t, r, w, mem, nil, "", 1)
				if res.Held == "" || res.Unknown == "" {
					t.Fatalf("the hold ended by itself after %d retries: %+v", i+1, res)
				}
			}
			if r.served() != before {
				t.Error("the proxy's configuration was changed while what it serves is unknown")
			}
			// A person removes the refused Ingress: every Ingress can go out, and it does.
			res, _, _ = settle(t, r, want(many(6)...), mem, nil, "", 1)
			if res.Held != "" || res.Unknown != "" || len(res.LeftOut) != 0 {
				t.Fatalf("still held once the refused Ingress is gone: %+v", res)
			}
		})
	}
}
