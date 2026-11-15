package ingress_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/ingress"
	"kevaso.com/core/sdk/kic"
)

// K-063: the per-Ingress apply (design §0.8) after an agent restart. A restarted agent has no
// memory: nil lastGood, "" for the plan in effect, an empty Memory. The proxy silo keeps its files.

// many is n Ingresses shop/iNN, each on its own host; those in bad are poisoned.
func many(n int, bad ...int) []kic.Route {
	var routes []kic.Route
	for i := 0; i < n; i++ {
		h := fmt.Sprintf("h%02d.example.com", i)
		if slices.Contains(bad, i) {
			h = fmt.Sprintf("%s%02d.example.com", poison, i)
		}
		routes = append(routes, route(fmt.Sprintf("shop/i%02d", i), h, 80+i))
	}
	return routes
}

// settle runs passes of the same desired state (each one using the last one's result, as the
// agent does) until nothing changes, at most n.
func settle(t *testing.T, r *rig, w ingress.Desired, m *ingress.Memory, good *kic.State, last string, n int) (ingress.EachResult, *kic.State, string) {
	t.Helper()
	var res ingress.EachResult
	for i := 0; i < n; i++ {
		var err error
		res, err = ingress.ApplyEach(context.Background(), r.exec, r.call, r.driver, w, good, last, m, 0)
		if err != nil {
			t.Fatal(err)
		}
		if res.Held == "" && res.Rejected == "" {
			g := res.Served
			good = &g
		}
		last = res.Hash
	}
	return res, good, last
}

func leftOutNames(res ingress.EachResult) []string { return slices.Sorted(maps.Keys(res.LeftOut)) }

// Invariant (a): an agent restart, with no change to any Ingress, changes nothing in the proxy's
// routes. Before the restart, two served Ingresses had broken edits (their last good versions are
// served) and a new one went out; many Ingresses, so the search for the culprits after a restart
// can't test them all within its bound.
func TestK063ARestartWithNoChangeChangesNoRoute(t *testing.T) {
	for _, blame := range []bool{true, false} {
		for _, r := range rigs(blame) {
			t.Run(fmt.Sprintf("%s/blame=%v", r.name, blame), func(t *testing.T) {
				m := &ingress.Memory{}
				_, good, last := settle(t, r, want(many(24)...), m, nil, "", 1)
				edited := want(append(many(24, 3, 11), route("shop/new", "new.example.com", 200))...)
				res, _, _ := settle(t, r, edited, m, good, last, 3)
				if got := leftOutNames(res); !slices.Equal(got, []string{"shop/i03", "shop/i11"}) {
					t.Fatalf("before the restart, left out %v (%v)", got, res.LeftOut)
				}
				before := r.served()
				for _, h := range []string{"h03.example.com", "h11.example.com", "new.example.com"} {
					if !strings.Contains(before, h) {
						t.Fatalf("before the restart, %s isn't served", h)
					}
				}

				// The agent restarts: nothing remembered, nothing changed.
				res, _, _ = settle(t, r, edited, &ingress.Memory{}, nil, "", 3)
				if after := r.served(); after != before {
					t.Errorf("a restart changed what the proxy serves:\nleft out %v\n%v", leftOutNames(res), res.LeftOut)
				}
				if got := leftOutNames(res); !slices.Equal(got, []string{"shop/i03", "shop/i11"}) {
					t.Errorf("after the restart, left out %v, want only the two broken ones: %v", got, res.LeftOut)
				}
			})
		}
	}
}

// Invariant (c): an Ingress left out because the bound on test runs was reached is tried again,
// with no change, on the next passes; every good one ends up served.
func TestK063EveryGoodIngressIsServedInTheEnd(t *testing.T) {
	for _, r := range rigs(false) {
		t.Run(r.name, func(t *testing.T) {
			res, _, _ := settle(t, r, want(append(many(40), route("zzz/bad", poison+".example.com", 82))...), &ingress.Memory{}, nil, "", 8)
			if got := leftOutNames(res); !slices.Equal(got, []string{"zzz/bad"}) {
				t.Errorf("after eight passes, left out %v, want only zzz/bad", got)
			}
			served := r.served()
			for i := 0; i < 40; i++ {
				if h := fmt.Sprintf("h%02d.example.com", i); !strings.Contains(served, h) {
					t.Errorf("%s isn't served", h)
				}
			}
		})
	}
}

// Invariant (d): blame is recomputed. An Ingress refused only together with another is served
// once the other is gone; and a proxy that names the line of a served Ingress in a conflict
// with a new one doesn't make the served one go.
func TestK063BlameIsRecomputed(t *testing.T) {
	for _, blame := range []bool{false, true} {
		t.Run(fmt.Sprintf("blame=%v", blame), func(t *testing.T) {
			r := pairRig(blame)
			m := &ingress.Memory{}
			_, good, last := settle(t, r, want(route("old/t", "paira.example.com", 80), route("vic/v", "v.example.com", 81)), m, nil, "", 1)
			res, good, last := settle(t, r, want(route("old/t", "paira.example.com", 80), route("vic/v", "v.example.com", 81), route("new/n", "pairb.example.com", 82)), m, good, last, 2)
			if got := leftOutNames(res); !slices.Equal(got, []string{"new/n"}) {
				t.Fatalf("left out %v, want new/n (the served one stays)", got)
			}
			if !strings.Contains(r.served(), "paira.example.com") {
				t.Fatal("the served Ingress was dropped")
			}
			res, _, _ = settle(t, r, want(route("vic/v", "v.example.com", 81), route("new/n", "pairb.example.com", 82)), m, good, last, 2)
			if len(res.LeftOut) != 0 || !strings.Contains(r.served(), "pairb.example.com") {
				t.Errorf("old/t is gone, yet new/n is still left out: %v", res.LeftOut)
			}
		})
	}
}

// The proxy names the line of the last of two conflicting Ingresses; the served one sorts last.
func TestK063BlameOnAServedIngressDoesNotDropIt(t *testing.T) {
	r := pairRig(true)
	m := &ingress.Memory{}
	_, good, last := settle(t, r, want(route("vic/v", "pairb.example.com", 81)), m, nil, "", 1)
	res, _, _ := settle(t, r, want(route("vic/v", "pairb.example.com", 81), route("att/x", "paira.example.com", 80)), m, good, last, 2)
	if !strings.Contains(r.served(), "pairb.example.com") || res.LeftOut["vic/v"] != "" {
		t.Errorf("the served Ingress was dropped on the proxy's blame: %v", res.LeftOut)
	}
}

// pairRig is an nginx whose config test refuses a config holding both "paira" and "pairb" (each is
// fine alone); blame: it names the line of the last of the two.
func pairRig(blame bool) *rig {
	r := rigs(blame)[0]
	if r.name != "nginx" {
		panic(r.name)
	}
	r.px.Check = func(cfg []byte, _ map[string][]byte) string {
		s := string(cfg)
		if !strings.Contains(s, "paira") || !strings.Contains(s, "pairb") {
			return ""
		}
		if !blame {
			return "nginx: [emerg] configuration refused"
		}
		n, lines := 0, strings.Split(s, "\n") // the backend line of the last one (in its marked section)
		for i, l := range lines {
			if strings.Contains(l, "paira") || strings.Contains(l, "pairb") {
				n = i + 1
			}
		}
		for n < len(lines) && !strings.Contains(lines[n-1], "proxy_pass") {
			n++
		}
		return fmt.Sprintf("nginx: [emerg] duplicate listen options in %s:%d", "/etc/nginx/nginx.conf", n)
	}
	return r
}

// recordPath is where the rig's driver keeps its record in the silo.
func recordPath(t *testing.T, r *rig) string {
	t.Helper()
	p, err := r.driver.Render(kic.State{Class: "public"})
	if err != nil {
		t.Fatal(err)
	}
	return ingress.RecordPath(p)
}

// Invariant (b): what is served is in the record next to the rendered config, written only once
// the proxy took it, with nothing staged left behind, readable only by its owner's processes
// (it holds keys), and outside the folder swept after each apply.
func TestK063TheRecordIsKeptNextToTheConfig(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			_, good, last := settle(t, r, want(many(3)...), m, nil, "", 1)
			settle(t, r, want(many(3, 1)...), m, good, last, 1) // refused: the record stays as it was
			path := recordPath(t, r)
			files, _, _ := r.px.Snapshot()
			if _, ok := files[path+".next"]; ok {
				t.Error("a staged record was left behind")
			}
			rec := string(files[path])
			if !strings.Contains(rec, "h01.example.com") || strings.Contains(rec, poison) {
				t.Errorf("the record isn't what the proxy took:\n%s", rec)
			}
			p, _ := r.driver.Render(want(many(3)...).State)
			if p.Dir != "" && strings.HasPrefix(path, strings.TrimSuffix(p.Dir, "/")+"/") {
				t.Errorf("the record %s is in %s, which is swept", path, p.Dir)
			}
			if !slices.ContainsFunc(r.px.Commands(), func(c string) bool { return strings.Contains(c, path+".next 0600") }) {
				t.Error("the record isn't written 0600")
			}
		})
	}
}

// Invariant (e): when the agent can't tell what the proxy serves (its record doesn't match, or
// can't be read), it applies nothing that leaves an Ingress out: the class is held, the proxy
// keeps what it runs. Once every Ingress passes, it is applied and known again.
func TestK063UnknownServedHoldsTheClass(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			_, good, last := settle(t, r, want(many(6)...), m, nil, "", 1)
			settle(t, r, want(many(6, 2)...), m, good, last, 1)
			r.px.Files[recordPath(t, r)] = []byte("{not json") // the record can't be read
			before := r.served()

			mem := &ingress.Memory{}
			res, _, _ := settle(t, r, want(many(6, 2)...), mem, nil, "", 3)
			if res.Held == "" || !strings.Contains(res.Held, "can't tell what the proxy serves") {
				t.Errorf("not held: %+v", res)
			}
			if r.served() != before {
				t.Error("the proxy's configuration was changed while what it serves is unknown")
			}
			if res.LeftOut["shop/i02"] == "" || len(res.LeftOut) != 1 {
				t.Errorf("held for %v, want shop/i02", res.LeftOut)
			}
			// Fixed: everything passes, it goes out, and the record is good again.
			res, _, _ = settle(t, r, want(append(many(6), route("shop/new", "new.example.com", 99))...), mem, nil, "", 1)
			if res.Held != "" || len(res.LeftOut) != 0 || !strings.Contains(r.served(), "new.example.com") {
				t.Fatalf("not applied once fixed: %+v", res)
			}
			res, _, _ = settle(t, r, want(append(many(6, 2), route("shop/new", "new.example.com", 99))...), &ingress.Memory{}, nil, "", 1)
			if res.Held != "" || !strings.Contains(res.LeftOut["shop/i02"], "last good version is still served") {
				t.Errorf("after another restart: %+v", res)
			}
		})
	}
}

// For a driver with a config file the record must match it: a config changed behind the agent's
// back (or a record that isn't the running one) is "unknown". An apply under way when the agent
// stopped (RECORD.next left) counts if it is what the proxy has.
func TestK063TheRecordIsCheckedAgainstTheRunningConfig(t *testing.T) {
	for _, r := range rigs(true) {
		if r.name == "kong" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			settle(t, r, want(many(3)...), m, nil, "", 1)
			path := recordPath(t, r)
			cfg, _ := r.driver.Render(want(many(3)...).State)
			// Stopped after the move: RECORD.next is the running config, RECORD an older one.
			files, _, _ := r.px.Snapshot()
			r.px.Files[path+".next"], r.px.Files[path] = files[path], []byte(`{"driver":"`+r.name+`","state":{"class":"public"}}`)
			res, _, _ := settle(t, r, want(many(3, 0)...), &ingress.Memory{}, nil, "", 1)
			if res.Held != "" || !strings.Contains(res.LeftOut["shop/i00"], "last good version is still served") {
				t.Errorf("RECORD.next matching the running config wasn't taken: %+v", res)
			}
			// Edited behind the agent's back.
			r.px.Files[cfg.Config.Path] = append(r.px.Files[cfg.Config.Path], []byte("\n# by hand\n")...)
			before := r.served()
			res, _, _ = settle(t, r, want(many(3, 0)...), &ingress.Memory{}, nil, "", 1)
			if res.Held == "" || r.served() != before {
				t.Errorf("a config that isn't the recorded one was taken as known: %+v", res)
			}
		})
	}
}

// For an admin-API driver an apply under way when the agent stopped (RECORD.next left) is
// resolved by asking the proxy (K-089): it still runs what RECORD says, so that is served; it runs
// something else (it took the apply, or another), so what it serves is unknown and the class held.
func TestK063AnAdminAPIApplyUnderWayIsUnknown(t *testing.T) {
	r := rigs(true)[2]
	if r.name != "kong" {
		t.Fatal(r.name)
	}
	settle(t, r, want(many(3)...), &ingress.Memory{}, nil, "", 1)
	r.px.Files[recordPath(t, r)+".next"] = []byte(`{}`)
	before := r.served()
	res, _, _ := settle(t, r, want(many(3, 1)...), &ingress.Memory{}, nil, "", 1)
	if res.Held != "" || r.served() != before || !strings.Contains(res.LeftOut["shop/i01"], "last good version is still served") {
		t.Errorf("Kong runs what the record says, yet: %+v", res)
	}
	settle(t, r, want(many(3)...), &ingress.Memory{}, nil, "", 1)
	r.px.Files[recordPath(t, r)+".next"] = []byte(`{}`)
	r.live = append([]byte(nil), r.live...)
	r.live = append(r.live, ' ') // Kong took something the record doesn't say
	before = r.served()
	res, _, _ = settle(t, r, want(many(3, 1)...), &ingress.Memory{}, nil, "", 1)
	if res.Held == "" || r.served() != before {
		t.Errorf("not held: %+v", res)
	}
}

// Invariant (c): an Ingress the proxy refused is tested again on a bounded backoff with no change
// at all, and served (its status cleared) once the proxy takes it; nothing runs before it's due.
func TestK063ARefusalIsRetriedOnTheBackoff(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			m := &ingress.Memory{Now: func() time.Time { return now }}
			w := want(route("shop/a", "a.example.com", 80), route("shop/b", poison+".example.com", 81))
			res, good, last := settle(t, r, w, m, nil, "", 1)
			if res.LeftOut["shop/b"] == "" {
				t.Fatalf("not refused: %+v", res)
			}
			// The proxy would take it now (say, the name it couldn't resolve resolves).
			fixed := func(cfg []byte, _ map[string][]byte) string { return "" }
			r.px.Check, r.call = fixed, okCall(r)
			checks, calls := r.px.Checks, r.calls
			for _, d := range []time.Duration{0, ingress.RetryMin / 2, ingress.RetryMin - time.Second} {
				now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC).Add(d)
				res, good, last = settle(t, r, w, m, good, last, 1)
				if res.Tests != 0 || r.px.Checks != checks || r.calls != calls || res.LeftOut["shop/b"] == "" {
					t.Fatalf("tested again before the backoff (%v): %+v", d, res)
				}
			}
			now = now.Add(time.Second)
			res, _, _ = settle(t, r, w, m, good, last, 1)
			if len(res.LeftOut) != 0 || !strings.Contains(r.served(), poison) {
				t.Errorf("not retried at the backoff: %+v", res)
			}
		})
	}
}

// The backoff doubles while the proxy still refuses, up to RetryMax (an hour, a pass a second).
func TestK063TheBackoffIsBounded(t *testing.T) {
	r := rigs(true)[0]
	start := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	now := start
	m := &ingress.Memory{Now: func() time.Time { return now }}
	w := want(route("shop/a", "a.example.com", 80), route("shop/b", poison+".example.com", 81))
	_, good, last := settle(t, r, w, m, nil, "", 1)
	var gaps []time.Duration
	at := now
	for ; now.Sub(start) < time.Hour; now = now.Add(time.Second) {
		checks := r.px.Checks
		_, good, last = settle(t, r, w, m, good, last, 1)
		if r.px.Checks != checks {
			gaps = append(gaps, now.Sub(at))
			at = now
		}
	}
	want := []time.Duration{ingress.RetryMin, 2 * ingress.RetryMin, 4 * ingress.RetryMin, 8 * ingress.RetryMin, 16 * ingress.RetryMin, ingress.RetryMax}
	if len(gaps) < len(want) || !slices.Equal(gaps[:len(want)], want) || slices.Max(gaps) > ingress.RetryMax {
		t.Errorf("retries %v apart, want %v then every %v", gaps, want, ingress.RetryMax)
	}
}

func okCall(r *rig) ingress.Caller {
	if r.call == nil {
		return nil
	}
	return func(_ context.Context, c kic.Call) (int, string, error) {
		if c.Method == "GET" && c.Path == "/status" {
			return 200, kongStatus(r.live), nil
		}
		r.calls++
		r.live = c.Body
		return 201, "", nil
	}
}

// Invariant (a) without an Ingress changed, (e): when the proxy starts refusing an Ingress it
// serves unchanged (alone or with a change elsewhere), the agent doesn't remove it: the class is
// held and what runs stays.
func TestK063AServedIngressIsNeverRemovedOnTheProxysWord(t *testing.T) {
	for _, blame := range []bool{true, false} {
		for _, r := range rigs(blame) {
			t.Run(fmt.Sprintf("%s/blame=%v", r.name, blame), func(t *testing.T) {
				m := &ingress.Memory{}
				_, good, last := settle(t, r, want(many(4)...), m, nil, "", 1)
				before := r.served()
				// h01 is now refused (the proxy's world changed), and a new Ingress arrives.
				sick := func(cfg []byte, _ map[string][]byte) string {
					if strings.Contains(string(cfg), "h01.example.com") {
						return "refused"
					}
					return ""
				}
				r.px.Check = sick
				if r.call != nil {
					r.call = func(_ context.Context, c kic.Call) (int, string, error) {
						if c.Method == "GET" && c.Path == "/status" {
							return 200, kongStatus(r.live), nil
						}
						r.calls++
						if strings.Contains(string(c.Body), "h01.example.com") {
							return 400, "refused", nil
						}
						r.live = c.Body
						return 201, "", nil
					}
				}
				res, _, _ := settle(t, r, want(append(many(4), route("shop/new", "new.example.com", 99))...), m, good, last, 2)
				if !strings.Contains(r.served(), "h01.example.com") {
					t.Errorf("a served, unchanged Ingress was removed: %+v", res)
				}
				// A config test tells the proxy refuses what it serves: held. An admin API runs it
				// already (an apply that changes nothing isn't sent), so only the new one waits.
				if r.name != "kong" && (res.Held == "" || r.served() != before) {
					t.Errorf("not held: %+v", res)
				}
			})
		}
	}
}

// The auditor's medium, on hold: a broken edit's last good version isn't put back over a host
// and path that another Ingress now holds (Desire gave it away when the edit moved the Ingress).
func TestK063ALastGoodVersionDoesNotTakeBackAClaim(t *testing.T) {
	for _, r := range rigs(true) {
		t.Run(r.name, func(t *testing.T) {
			m := &ingress.Memory{}
			_, good, last := settle(t, r, want(route("shop/a", "a.example.com", 80)), m, nil, "", 1)
			// a moves to a broken host; b takes a.example.com.
			res, _, _ := settle(t, r, want(route("shop/a", poison+".example.com", 80), route("shop/b", "a.example.com", 81)), m, good, last, 2)
			if res.Held != "" || res.LeftOut["shop/b"] != "" || !strings.Contains(res.LeftOut["shop/a"], "shop/b now has a.example.com/") {
				t.Fatalf("%+v", res)
			}
			if !strings.Contains(r.served(), "81") {
				t.Errorf("the newcomer isn't served:\n%s", r.served())
			}
		})
	}
}

// Invariant (d), the auditor's pair: two new Ingresses fine alone but refused together, among
// others, on a proxy that serves nothing of ours yet. Only one of the two is held back (found by
// testing); the others are served; and a restart then changes nothing.
func TestK063APairRefusedTogetherHoldsBackOnlyOne(t *testing.T) {
	r := pairRig(false)
	w := want(route("att/a1", "paira.example.com", 80), route("vic/v1", "v1.example.com", 81),
		route("vic/v2", "v2.example.com", 82), route("zzz/a2", "pairb.example.com", 83))
	res, _, _ := settle(t, r, w, &ingress.Memory{}, nil, "", 1)
	if res.Held != "" || len(res.LeftOut) != 1 || res.LeftOut["vic/v1"] != "" || res.LeftOut["vic/v2"] != "" {
		t.Fatalf("left out %v (%s)", res.LeftOut, res.Held)
	}
	before := r.served()
	if !strings.Contains(before, "v1.example.com") || !strings.Contains(before, "v2.example.com") {
		t.Fatal("an innocent one isn't served")
	}
	settle(t, r, w, &ingress.Memory{}, nil, "", 2)
	if r.served() != before {
		t.Error("a restart changed what the proxy serves")
	}
}
