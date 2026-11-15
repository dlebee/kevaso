package ingress_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	kicdrivers "kevaso.com/core/builtin/kic"
	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/sdk/kic"
)

// K-089: the invariant, for every built-in driver through the driver interface: the absence,
// loss, truncation or corruption of Kevaso's own record of what it applied never causes a change
// to what the proxy is serving. With no usable record the agent establishes what is served from
// the proxy itself before it changes anything; if it can't tell, the class is held and the proxy
// left as it is, with the reason on the class's status.

// TestK089RigsCoverEveryDriver: the rigs these tests run on are every built-in driver.
func TestK089RigsCoverEveryDriver(t *testing.T) {
	var got []string
	for _, r := range rigs(false) {
		got = append(got, r.name)
	}
	if want := slices.Sorted(maps.Keys(kicdrivers.Builtin())); !slices.Equal(slices.Sorted(slices.Values(got)), want) {
		t.Fatalf("rigs for %v, built-in drivers %v", got, want)
	}
}

// watch makes r report every moment what the proxy serves differs from now: after every command
// run in the silo and every call to its admin API. changes is how many moments it did.
func watch(r *rig) (changes func() int, stop func()) {
	before, n := r.served(), 0
	exec, call := r.exec, r.call
	r.exec = func(ctx context.Context, argv []string, stdin []byte) (int, string, error) {
		code, out, err := exec(ctx, argv, stdin)
		if r.served() != before {
			n++
		}
		return code, out, err
	}
	if call != nil {
		r.call = func(ctx context.Context, c kic.Call) (int, string, error) {
			st, body, err := call(ctx, c)
			if r.served() != before {
				n++
			}
			return st, body, err
		}
	}
	return func() int { return n }, func() { r.exec, r.call = exec, call }
}

// served24 is the K-063 scene: 24 Ingresses served, then two of them (i03, i11) edited into
// something the proxy refuses (their last good versions stay served) and a new one served too.
func served24(t *testing.T, r *rig) ingress.Desired {
	t.Helper()
	m := &ingress.Memory{}
	_, good, last := settle(t, r, want(many(24)...), m, nil, "", 1)
	edited := want(append(many(24, 3, 11), route("shop/new", "new.example.com", 200))...)
	res, _, _ := settle(t, r, edited, m, good, last, 3)
	if got := leftOutNames(res); !slices.Equal(got, []string{"shop/i03", "shop/i11"}) {
		t.Fatalf("before the restart, left out %v (%v)", got, res.LeftOut)
	}
	return edited
}

// restartUnchanged restarts the agent (no memory) for a few passes and checks that nothing the
// proxy serves changed at any moment; known: the agent must also have told what is served (the
// two broken ones are left out and nothing else, the class not held).
func restartUnchanged(t *testing.T, r *rig, w ingress.Desired, known bool) ingress.EachResult {
	t.Helper()
	changes, stop := watch(r)
	defer stop()
	res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 3)
	if n := changes(); n > 0 {
		t.Errorf("what the proxy serves changed at %d moments after a restart (held %q, left out %v)", n, res.Held, res.LeftOut)
	}
	if known {
		if res.Held != "" || !slices.Equal(leftOutNames(res), []string{"shop/i03", "shop/i11"}) {
			t.Errorf("what is served should be known: held %q, left out %v", res.Held, res.LeftOut)
		}
	} else if res.Held == "" && !slices.Equal(leftOutNames(res), []string{"shop/i03", "shop/i11"}) {
		t.Errorf("neither held nor the two broken ones alone left out: %v", res.LeftOut)
	}
	if res.Held != "" && !strings.Contains(res.Held, "can't tell") {
		t.Errorf("held without saying the agent can't tell what is served: %q", res.Held)
	}
	return res
}

// The record deleted (the first restart after upgrading from a build that wrote none, or Kong's
// record in /tmp wiped while Kong keeps its config), emptied, truncated or corrupted.
func TestK089ALostRecordChangesNothing(t *testing.T) {
	damage := map[string]func(b []byte) ([]byte, bool){
		"deleted":   func([]byte) ([]byte, bool) { return nil, false },
		"empty":     func([]byte) ([]byte, bool) { return []byte{}, true },
		"blank":     func([]byte) ([]byte, bool) { return []byte(" \n\t\n"), true },
		"truncated": func(b []byte) ([]byte, bool) { return b[:len(b)/2], true },
		"corrupt":   func([]byte) ([]byte, bool) { return []byte("{not json"), true },
		"other":     func([]byte) ([]byte, bool) { return []byte(`{"driver":"nope","state":{}}`), true },
	}
	for _, name := range slices.Sorted(maps.Keys(damage)) {
		for _, blame := range []bool{false, true} {
			for _, r := range rigs(blame) {
				t.Run(fmt.Sprintf("%s/%s/blame=%v", name, r.name, blame), func(t *testing.T) {
					w := served24(t, r)
					p := recordPath(t, r)
					b, keep := damage[name](r.px.Files[p])
					delete(r.px.Files, p)
					if keep {
						r.px.Files[p] = b
					}
					restartUnchanged(t, r, w, false)
				})
			}
		}
	}
}

// A record from an older build (no digest of the config, no fingerprint of the proxy): a config
// file is still recognised by rendering it; an admin API can't check it, so it isn't trusted.
func TestK089ARecordOfAnOlderFormat(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			w := served24(t, r)
			p := recordPath(t, r)
			var rec map[string]json.RawMessage
			if err := json.Unmarshal(r.px.Files[p], &rec); err != nil {
				t.Fatal(err)
			}
			delete(rec, "config")
			delete(rec, "proxy")
			r.px.Files[p], _ = json.Marshal(rec)
			restartUnchanged(t, r, w, r.name != "kong")
		})
	}
}

// An apply under way when the agent stopped: only RECORD.next is there. Resolved by comparing it
// with what the proxy runs, like RECORD.
func TestK089OnlyANextRecordLeft(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			w := served24(t, r)
			p := recordPath(t, r)
			r.px.Files[p+".next"] = r.px.Files[p]
			delete(r.px.Files, p)
			// A config file's record carries its digest; Kong's .next has no fingerprint yet
			// (it is written before the apply), so it can't be recognised: held.
			restartUnchanged(t, r, w, r.name != "kong")
		})
	}
}

// The record is there, but the proxy's config was changed by hand inside an Ingress that didn't
// change: unknown, held, nothing changed.
func TestK089AHandEditIsNotExplained(t *testing.T) {
	for _, r := range rigs(false) {
		if r.name == "kong" {
			continue // no config to edit by hand (Kong's own word for what it runs: below)
		}
		t.Run(r.name, func(t *testing.T) {
			w := served24(t, r)
			cfg := configPath(t, r)
			edited := strings.Replace(string(r.px.Files[cfg]), "10.64.0.5:85", "10.64.0.9:85", 1)
			if edited == string(r.px.Files[cfg]) {
				t.Fatal("nothing to edit")
			}
			r.px.Files[cfg] = []byte(edited)
			if res := restartUnchanged(t, r, w, false); res.Held == "" {
				t.Errorf("a hand edit inside an unchanged Ingress wasn't held: %v", res.LeftOut)
			}
		})
	}
}

// The proxy restarted with an older config (an older copy of the silo, Kong reloaded from an
// older file) while the record is the last one: the record doesn't match, nothing changes.
func TestK089AProxyOnAnOlderConfig(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			_, _, _ = settle(t, r, want(many(24)...), &ingress.Memory{}, nil, "", 1)
			var older []byte
			if r.name == "kong" {
				older = append([]byte(nil), r.live...)
			} else {
				older = append([]byte(nil), r.px.Files[configPath(t, r)]...)
			}
			w := served24(t, r)
			if r.name == "kong" {
				r.live = older
			} else {
				r.px.Files[configPath(t, r)] = older
			}
			restartUnchanged(t, r, w, false)
		})
	}
}

// No record and a proxy that serves nothing of ours (the image's own config; a Kong that runs
// none): established from the proxy, so §0.8 still holds back only the broken Ingress.
func TestK089AFreshProxyHoldsBackOnlyTheBrokenOne(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			res, _, _ := settle(t, r, want(append(many(6), route("shop/bad", poison+".example.com", 99))...), &ingress.Memory{}, nil, "", 2)
			if res.Held != "" || !slices.Equal(leftOutNames(res), []string{"shop/bad"}) {
				t.Fatalf("held %q, left out %v", res.Held, res.LeftOut)
			}
			for i := 0; i < 6; i++ {
				if h := fmt.Sprintf("h%02d.example.com", i); !strings.Contains(r.served(), h) {
					t.Errorf("%s isn't served", h)
				}
			}
		})
	}
}

// No record, and the running config differs from a fresh render only inside Ingresses' own
// parts: those are taken as changed and the normal rule applies (a config-file driver). A broken
// newcomer on a served host is left out alone; the changed one goes out.
func TestK089DifferencesInsideAnIngressAreItsChange(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			_, _, _ = settle(t, r, want(many(6)...), &ingress.Memory{}, nil, "", 1)
			delete(r.px.Files, recordPath(t, r))
			routes := many(6)
			routes[2].Backend.Port = 1234 // i02 changed in its own part
			bad := route("shop/x", "h01.example.com", 99)
			bad.Path, bad.Backend.Address = "/x", poison // a newcomer the proxy refuses, on h01
			w := want(append(routes, bad)...)
			if r.name == "kong" {
				restartUnchanged(t, r, w, false) // no config to compare: Kong can't tell, held
				return
			}
			res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 2)
			if res.Held != "" || !slices.Equal(leftOutNames(res), []string{"shop/x"}) {
				t.Fatalf("held %q, left out %v", res.Held, res.LeftOut)
			}
			if !strings.Contains(r.served(), "10.64.0.5:1234") {
				t.Error("i02's change isn't served")
			}
		})
	}
}

// The same, but the changed Ingress is itself refused: its served version isn't known, so it
// can't be put back, and removing it isn't explained by anything: held, nothing changes.
func TestK089AChangedIngressWithNoLastGoodVersionHolds(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			_, _, _ = settle(t, r, want(many(6)...), &ingress.Memory{}, nil, "", 1)
			delete(r.px.Files, recordPath(t, r))
			routes := many(6)
			routes[4].Backend.Address = poison // i04 changed, inside its own part, into a refusal
			changes, stop := watch(r)
			res, _, _ := settle(t, r, want(routes...), &ingress.Memory{}, nil, "", 2)
			stop()
			if n := changes(); n > 0 || res.Held == "" {
				t.Errorf("changed %d times, held %q, left out %v", n, res.Held, res.LeftOut)
			}
		})
	}
}

func configPath(t *testing.T, r *rig) string {
	t.Helper()
	p, err := r.driver.Render(kic.State{Class: "public"})
	if err != nil || p.Config.Path == "" {
		t.Fatalf("no config file: %v", err)
	}
	return p.Config.Path
}
