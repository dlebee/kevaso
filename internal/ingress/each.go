package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	"kevaso.com/core/sdk/kic"
)

// Per-Ingress apply (design §0.8, 2026-11-14: "a held ingress class holds back only the broken
// Ingress"). A class's desired state is rendered and checked per Ingress: one that its driver
// refuses, that won't render, or that makes the proxy's own config test fail is left out with the
// reason, and every other Ingress, new ones included, is applied. When the proxy refuses the whole
// configuration, the culprit is found by the driver's blame first, then by testing the Ingresses
// that changed since the last good configuration (each on its own, bisecting), never more than a
// bound of test runs per change. The class is held (nothing new applied, the last good config
// stays) only when even the configuration with no user Ingress is refused. It works through the
// driver interface alone: a driver with a config test (Plan.Check) is tested without touching the
// running proxy; an admin-API driver, whose only test is the apply itself, relies on its blame and
// otherwise falls back to the Ingresses it served before, which never drops a working route.

// DefaultTests bounds the config test runs one change may cost.
const DefaultTests = 12

// Memory is what ApplyEach keeps between passes for one controller silo (the caller holds it):
// the outcome for the desired state it last saw, so an unchanged state costs no test run at all,
// and what the proxy's test said of each Ingress by its fragment's content, so a refused Ingress is
// tested again only when it (or the class's options) changes.
type Memory struct {
	verdicts map[string]string // fragment key → why it was refused
	want     string            // the desired state last handled
	outcome  EachResult        // and how that went
}

// EachResult is how a per-Ingress apply went.
type EachResult struct {
	Result
	// LeftOut are the Ingresses not in the configuration now in effect, and why.
	LeftOut map[string]string
	// Held: even the configuration with no user Ingress was refused (the proxy's words). Nothing
	// new is applied; the last good configuration stays.
	Held string
	// Served is the state now in effect (what the next change is compared with), valid when
	// Held is empty and Result.Rejected is empty.
	Served kic.State
	Tests  int // config test runs (and admin-API attempts) spent
}

// fragment is what one Ingress brings into a State.
type fragment struct {
	Routes       []kic.Route       `json:"routes,omitempty"`
	Certificates []kic.Certificate `json:"certificates,omitempty"`
}

func split(s kic.State) (base kic.State, by map[string]fragment) {
	base = kic.State{Class: s.Class, Options: s.Options, Challenges: s.Challenges}
	by = map[string]fragment{}
	for _, r := range s.Routes {
		f := by[r.Ingress]
		f.Routes = append(f.Routes, r)
		by[r.Ingress] = f
	}
	for _, c := range s.Certificates {
		f := by[c.Ingress]
		f.Certificates = append(f.Certificates, c)
		by[c.Ingress] = f
	}
	return base, by
}

// join is base with the fragments of who, in State order.
func join(base kic.State, by map[string]fragment, who []string) kic.State {
	s := base
	s.Routes, s.Certificates = nil, nil
	for _, w := range who {
		s.Routes = append(s.Routes, by[w].Routes...)
		s.Certificates = append(s.Certificates, by[w].Certificates...)
	}
	sortState(&s)
	return s
}

// sortState puts routes and certificates in the order Desire gives them.
func sortState(s *kic.State) {
	sort.SliceStable(s.Routes, func(i, j int) bool {
		a, b := s.Routes[i], s.Routes[j]
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if len(a.Path) != len(b.Path) {
			return len(a.Path) > len(b.Path)
		}
		return a.Path < b.Path
	})
	sort.SliceStable(s.Certificates, func(i, j int) bool { return s.Certificates[i].Name < s.Certificates[j].Name })
}

func hashOf(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:10])
}

// ApplyEach applies want's state to the proxy, per Ingress. lastGood is the state last served in
// full (nil: unknown, every Ingress counts as changed); last is the hash of the plan in effect
// (as for Apply; "" or "?": unknown); m is kept between calls (nil: nothing kept); maxTests bounds
// the test runs one change may cost (0: DefaultTests). An error means it couldn't be done now (try
// again; nothing is remembered).
func ApplyEach(ctx context.Context, exec Exec, call Caller, d kic.Driver, want Desired, lastGood *kic.State, last string, m *Memory, maxTests int) (EachResult, error) {
	if maxTests <= 0 {
		maxTests = DefaultTests
	}
	if m == nil {
		m = &Memory{}
	}
	wantKey := hashOf(want) + "@" + d.Info().Name
	if m.want == wantKey && last != "" && last != "?" && last == m.outcome.Hash {
		same := m.outcome
		same.Changed, same.Tests = false, 0
		return same, nil // nothing changed since: no test run
	}
	r, err := applyEach(ctx, exec, call, d, want, lastGood, last, m, maxTests)
	if err == nil {
		m.want, m.outcome = wantKey, r
	} else {
		m.want = ""
	}
	return r, err
}

func applyEach(ctx context.Context, exec Exec, call Caller, d kic.Driver, want Desired, lastGood *kic.State, last string, m *Memory, maxTests int) (EachResult, error) {
	if m.verdicts == nil {
		m.verdicts = map[string]string{}
	}
	v := m.verdicts
	out := EachResult{LeftOut: map[string]string{}}
	maps.Copy(out.LeftOut, want.Refused) // refused by Desire: never in the state
	base, by := split(want.State)
	baseKey := hashOf(base.Options)
	keyOf := func(who string) string { return who + "@" + hashOf(by[who]) + "@" + baseKey }
	{ // keep only the verdicts of fragments that still exist
		live := map[string]bool{}
		for who := range by {
			live[keyOf(who)] = true
		}
		maps.DeleteFunc(v, func(k, _ string) bool { return !live[k] })
	}

	// The class's own part first: if even that can't go out, the class is held.
	if err := kic.Validate(d, base); err != nil {
		out.Held = err.Error()
		return out, nil
	}
	if _, err := d.Render(base); err != nil {
		out.Held = "render: " + err.Error()
		return out, nil
	}

	var before map[string]fragment
	if lastGood != nil {
		_, before = split(*lastGood)
	}
	alone := func(f fragment) error {
		one := join(base, map[string]fragment{"": f}, []string{""})
		if err := kic.Validate(d, one); err != nil {
			return err
		}
		if _, err := d.Render(one); err != nil {
			return fmt.Errorf("render: %w", err)
		}
		return nil
	}
	// hold puts who's last good version back in place of its refused change, so only the change
	// is held back and what it served keeps being served. false: it has none to go back to.
	hold := func(who, why string) bool {
		f, ok := before[who]
		if cur, has := by[who]; !ok || (has && hashOf(cur) == hashOf(f)) || alone(f) != nil {
			return false
		}
		by[who] = f
		out.LeftOut[who] = "its change is refused, its last good version is still served: " + why
		return true
	}
	// Refused by Desire (the driver won't take an annotation, a host): it has no fragment now.
	for _, who := range slices.Sorted(maps.Keys(want.Refused)) {
		hold(who, want.Refused[who])
	}

	// Each Ingress against the driver alone (no proxy needed), and what the proxy said before.
	var keep []string
	for _, who := range slices.Sorted(maps.Keys(by)) {
		why := ""
		if err := alone(by[who]); err != nil {
			why = err.Error()
		} else if w, ok := v[keyOf(who)]; ok {
			why = w
		}
		if why != "" && !hold(who, why) {
			out.LeftOut[who] = why
			continue
		}
		keep = append(keep, who)
	}
	changed := func(who string) bool {
		f, ok := before[who]
		return lastGood == nil || !ok || hashOf(f) != hashOf(by[who])
	}
	// refuse holds back who: remember, the proxy refused it for what it is (kept until it
	// changes), not merely alongside others; back, its last good version may take its place.
	refuse := func(who []string, why string, remember, back bool) {
		var out2 []string
		for _, w := range who {
			if remember {
				v[keyOf(w)] = why
			}
			if back && hold(w, why) {
				continue
			}
			out.LeftOut[w] = why
			out2 = append(out2, w)
		}
		keep = slices.DeleteFunc(keep, func(w string) bool { return slices.Contains(out2, w) })
	}

	// try applies base with keep; it's a test too (the proxy checks before it loads anything).
	try := func() (Result, kic.Plan, error) {
		st := join(base, by, keep)
		p, err := d.Render(st)
		if err != nil {
			return Result{Rejected: "render: " + err.Error()}, p, nil
		}
		out.Tests++
		r, err := Apply(ctx, exec, call, d, p, last)
		if err == nil && r.Rejected == "" {
			out.Served = st
		}
		return r, p, err
	}
	res, plan, err := try()
	if err != nil || res.Rejected == "" {
		out.Result = res
		return out, err
	}

	// The proxy refused it. Its blame first: those are out, the rest goes again.
	if blamed := intersect(res.Blamed, keep); len(blamed) > 0 && out.Tests < maxTests-1 {
		refuse(blamed, "the proxy refused the configuration with it: "+res.Rejected, true, true)
		if res, plan, err = try(); err != nil || res.Rejected == "" {
			out.Result = res
			return out, err
		}
	}

	testable := len(plan.Check) > 0 && plan.Config.Path != ""
	var suspects, trusted []string
	for _, w := range keep {
		if changed(w) {
			suspects = append(suspects, w)
		} else {
			trusted = append(trusted, w)
		}
	}
	if len(suspects) > 0 && (testable || plan.Reload.Call != nil) {
		changedLive := false
		var test func(who []string) (string, bool)
		ctxSet := trusted
		if testable {
			// A config test: run on the side, the running proxy never sees it.
			test = func(who []string) (string, bool) {
				if out.Tests >= maxTests-1 { // one is kept for the apply after
					return "", false
				}
				p, err := d.Render(join(base, by, who))
				if err != nil {
					return "render: " + err.Error(), true
				}
				out.Tests++
				why, err := Test(ctx, exec, p)
				if err != nil {
					return "", false
				}
				return why, true
			}
			// What served before still passes? Then only the changed ones can be at fault.
			if why, ok := test(trusted); ok && why != "" {
				suspects, ctxSet = keep, nil // what passed before fails now: everything is suspect
			}
		} else {
			// An admin API: its only test is the apply. Applying what served before plus some of
			// the changed Ingresses never drops a route that worked, so a part it accepts stays
			// applied, and the context grows with it.
			test = func(who []string) (string, bool) {
				if out.Tests >= maxTests-1 {
					return "", false
				}
				st := join(base, by, who)
				p, err := d.Render(st)
				if err != nil {
					return "render: " + err.Error(), true
				}
				out.Tests++
				r, err := Apply(ctx, exec, call, d, p, last)
				if err != nil {
					return "", false
				}
				if r.Rejected != "" {
					return r.Rejected, true
				}
				last, out.Served, ctxSet = r.Hash, st, slices.Clone(who)
				changedLive = changedLive || r.Changed
				return "", true
			}
		}
		bad, unknown := bisect(suspects, func(sub []string) (string, bool) {
			return test(append(slices.Clone(ctxSet), sub...))
		})
		for _, b := range bad {
			refuse([]string{b.who}, "the proxy refused it: "+b.why, true, true)
		}
		if len(unknown) > 0 {
			// Not remembered: they are tried again on the next pass.
			refuse(unknown, fmt.Sprintf("not checked yet: finding the Ingress the proxy refuses took more than %d test runs", maxTests), false, true)
		}
		if res, _, err = try(); err != nil || res.Rejected == "" {
			res.Changed = res.Changed || changedLive
			out.Result = res
			return out, err
		}
	}

	// Still refused (an admin-API driver that couldn't tell, or Ingresses fine alone but not
	// together): fall back to what was served before, leaving out everything that changed.
	if left := intersect(suspects, keep); len(left) > 0 {
		refuse(left, "the proxy refused the configuration with the Ingresses changed since the last good one, and couldn't say which: "+res.Rejected, false, true)
		if res, _, err = try(); err != nil || res.Rejected == "" {
			out.Result = res
			return out, err
		}
	}
	// Then the class's own part alone: if the proxy refuses even that, the class is held.
	refuse(slices.Clone(keep), "the proxy refused every configuration with it: "+res.Rejected, false, false)
	if res, _, err = try(); err != nil || res.Rejected == "" {
		out.Result = res
		return out, err
	}
	out.Held = res.Rejected
	for w := range by { // nothing is applied: none of these is "refused" for what it is
		delete(v, keyOf(w))
	}
	out.Result = res
	return out, nil
}

type culprit struct{ who, why string }

// bisect finds the members of s that fail test (given with the rest of the context): halves that
// pass are cleared at once, a single that fails is a culprit. unknown: left when the test budget
// ran out (test answers ok=false).
func bisect(s []string, test func([]string) (string, bool)) (bad []culprit, unknown []string) {
	if len(s) == 0 {
		return nil, nil
	}
	why, ok := test(s)
	if !ok {
		return nil, slices.Clone(s)
	}
	if why == "" {
		return nil, nil
	}
	if len(s) == 1 {
		return []culprit{{s[0], why}}, nil
	}
	h := len(s) / 2
	b1, u1 := bisect(s[:h], test)
	b2, u2 := bisect(s[h:], test)
	return append(b1, b2...), append(u1, u2...)
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// Test runs the proxy's config test on p without changing what the proxy runs: its missing
// supporting files and the config are written next to the running ones (PATH.test), the check
// runs, and everything written is removed again. why is the proxy's refusal ("" if it passed).
func Test(ctx context.Context, exec Exec, p kic.Plan) (why string, err error) {
	if len(p.Check) == 0 || p.Config.Path == "" {
		return "", fmt.Errorf("this driver's plans have no config test")
	}
	run := func(argv []string, stdin []byte) error {
		code, out, err := exec(ctx, argv, stdin)
		if err == nil && code != 0 {
			err = fmt.Errorf("%s: exit %d: %s", argv[0], code, tail(out))
		}
		return err
	}
	have := map[string]bool{}
	if p.Dir != "" {
		code, out, err := exec(ctx, ListCmd(p.Dir), nil)
		if err != nil {
			return "", err
		}
		if code != 0 {
			return "", fmt.Errorf("list %s: exit %d: %s", p.Dir, code, tail(out))
		}
		for _, n := range strings.Fields(out) {
			have[strings.TrimSuffix(p.Dir, "/")+"/"+n] = true
		}
	}
	staged := []string{p.Config.Path + ".test"}
	defer func() { _ = run(RemoveCmd(staged...), nil) }()
	for _, f := range p.Files {
		if have[f.Path] {
			continue
		}
		if err := run(WriteCmd(f.Path, mode(f)), f.Data); err != nil {
			return "", fmt.Errorf("write %s: %w", f.Path, err)
		}
		staged = append(staged, f.Path)
	}
	if err := run(WriteCmd(staged[0], mode(p.Config)), p.Config.Data); err != nil {
		return "", fmt.Errorf("write %s: %w", staged[0], err)
	}
	argv := make([]string, len(p.Check))
	for i, a := range p.Check {
		argv[i] = strings.ReplaceAll(a, kic.ConfigToken, staged[0])
	}
	code, out, err := exec(ctx, argv, nil)
	if err != nil {
		return "", fmt.Errorf("check: %w", err)
	}
	if code != 0 {
		why = tail(strings.ReplaceAll(out, staged[0], p.Config.Path))
		if why == "" {
			why = fmt.Sprintf("%s exited %d", argv[0], code)
		}
		return why, nil
	}
	return "", nil
}

// LeftOutMessage is a controller's Rejected text for Ingresses left out: one "ingress WHO: WHY"
// segment each, in name order (Refused finds an Ingress's own).
func LeftOutMessage(left map[string]string) string {
	var parts []string
	for _, who := range slices.Sorted(maps.Keys(left)) {
		parts = append(parts, "ingress "+who+": "+oneLine(left[who]))
	}
	return strings.Join(parts, "; ")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// segmentFor is who's own part of a LeftOutMessage, or the whole text if it has none.
func segmentFor(msg, who string) string {
	mark := "ingress " + who + ": "
	i := strings.Index(msg, mark)
	if i < 0 {
		return msg
	}
	rest := msg[i+len(mark):]
	if j := strings.Index(rest, "; ingress "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

var (
	memMu    sync.Mutex
	memories = map[string]*Memory{}
)

// MemoryOf is the Memory kept for one controller silo (by its UID), for callers that keep none
// of their own. A silo that stops being a controller leaves a few hashes behind.
func MemoryOf(uid string) *Memory {
	memMu.Lock()
	defer memMu.Unlock()
	m := memories[uid]
	if m == nil {
		m = &Memory{}
		memories[uid] = m
	}
	return m
}
