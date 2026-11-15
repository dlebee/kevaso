package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"kevaso.com/core/sdk/kic"
)

// Per-Ingress apply (design §0.8, 2026-11-14: "a held ingress class holds back only the broken
// Ingress"). A class's desired state is rendered and checked per Ingress: one that its driver
// refuses, that won't render, or that makes the proxy's own config test fail is left out with the
// reason (at its last good version, if it had one), and every other Ingress, new ones included, is
// applied. When the proxy refuses the whole configuration, the culprit is found by the driver's
// blame first, then by testing the Ingresses that changed since the last good configuration (each
// on its own, bisecting), never more than a bound of test runs per change. It works through the
// driver interface alone: a driver with a config test (Plan.Check) is tested without touching the
// running proxy; an admin-API driver, whose only test is the apply itself, relies on its blame and
// otherwise applies what it served before plus what it can, which never drops a working route.
//
// What the proxy serves is never assumed (K-063). It is what this Memory last had the proxy
// accept, else the record kept in the silo next to the rendered config (record.go), which a
// restarted agent reads back and checks against the running config. Two rules keep the running
// proxy whole:
//   - A route the proxy serves is removed only because its Ingress changed (or went). An Ingress
//     whose served version the proxy now refuses, or one that couldn't be checked, is never left
//     out: the class is held instead, and the running configuration stays (as before §0.8).
//   - When what the proxy serves is unknown (no record matches it), nothing is applied unless no
//     Ingress at all is left out; until then the class is held.
//
// Verdicts are recomputed, not remembered for ever: what the proxy said of an Ingress tested alone
// stands until it or the class's options change; what it said of one only together with others
// stands until anything in the class changes; and every one is tested again on a bounded backoff
// (RetryMin, doubling up to RetryMax), so an Ingress that passes again is served again and its
// status clears. An outcome with an Ingress not checked yet is never reused: the next pass goes on.
// Blame and bisecting only ever convict an Ingress that changed since what the proxy serves; one
// the proxy serves unchanged is not convicted because it was there first or because a line of its
// is where the proxy's error points.

// DefaultTests bounds the config test runs one change may cost.
const DefaultTests = 12

// The backoff on which what the proxy refused is tested again with no change.
const (
	RetryMin = 30 * time.Second
	RetryMax = 10 * time.Minute
)

// Memory is what ApplyEach keeps between passes for one controller silo (the caller holds it):
// what the proxy was last seen to accept, the outcome for the desired state it last saw (so an
// unchanged state costs no test run until the backoff is due), and what the proxy's test said of
// each refused Ingress. A new Memory is what a restarted agent has: ApplyEach then reads the
// silo's record.
type Memory struct {
	// Now is the clock for the retry backoff (nil: time.Now).
	Now func() time.Time

	served   *kic.State        // what the proxy last accepted from this Memory's applies (nil: ask the record)
	recorded string            // the state the silo's record holds (hashOf), "" if not known
	verdicts map[string]string // fragment key → why it was refused
	want     string            // the desired state last handled
	outcome  EachResult        // and how that went
	retryAt  time.Time         // when what the proxy refused is tested again (zero: nothing is)
	backoff  time.Duration
}

// EachResult is how a per-Ingress apply went.
type EachResult struct {
	Result
	// LeftOut are the Ingresses not in the configuration now in effect, and why (when Held: the
	// Ingresses the class is held for, as far as could be told).
	LeftOut map[string]string
	// Held: nothing new is applied; the configuration the proxy runs stays. Why: even the
	// configuration with no user Ingress was refused, or applying would remove a route the proxy
	// serves without its Ingress having changed, or what the proxy serves is unknown and some
	// Ingress would be left out.
	Held string
	// Served is the state now in effect (what the next change is compared with), valid when
	// Held is empty and Result.Rejected is empty.
	Served kic.State
	Tests  int // config test runs (and admin-API attempts) spent
	// RecordProblem: the silo's record of what was applied couldn't be written. After a restart
	// the class is then held until every Ingress passes.
	RecordProblem string

	retry     bool // left out or held on the proxy's word: tested again on the backoff
	unchecked bool // an Ingress was left out not checked yet: tested again on the next pass
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

// errHold stops a pass: applying would remove a route the proxy serves (EachResult.Held says why).
var errHold = errors.New("held")

// ApplyEach applies want's state to the proxy, per Ingress. lastGood is what the proxy serves, if
// the caller knows (nil: what m last had it accept, else the silo's record); last is the hash of
// the plan in effect (as for Apply; "" or "?": unknown); m is kept between calls (nil: nothing
// kept); maxTests bounds the test runs one change may cost (0: DefaultTests). exec must reach the
// controller silo for every driver (the record is kept there). An error means it couldn't be
// done now (try again; nothing is remembered).
func ApplyEach(ctx context.Context, exec Exec, call Caller, d kic.Driver, want Desired, lastGood *kic.State, last string, m *Memory, maxTests int) (EachResult, error) {
	if maxTests <= 0 {
		maxTests = DefaultTests
	}
	if m == nil {
		m = &Memory{}
	}
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	wantKey := hashOf(want) + "@" + d.Info().Name
	due := !m.retryAt.IsZero() && !now().Before(m.retryAt)
	if m.want == wantKey && last != "?" && last == m.outcome.Hash && !m.outcome.unchecked && !due {
		same := m.outcome
		same.Changed, same.Tests, same.RecordProblem = false, 0, ""
		return same, nil // nothing changed since, and nothing is due: no test run
	}
	if due {
		m.verdicts = nil // what the proxy refused is asked again, not remembered
	}
	r, err := applyEach(ctx, exec, call, d, want, lastGood, last, m, maxTests)
	if errors.Is(err, errHold) {
		err = nil
	}
	if err != nil {
		// It may be half done: what the proxy serves is read back from the record next time.
		m.want, m.served = "", nil
		return r, err
	}
	switch {
	case !r.retry:
		m.retryAt, m.backoff = time.Time{}, 0
	case m.retryAt.IsZero() || due:
		m.backoff = min(max(2*m.backoff, RetryMin), RetryMax)
		m.retryAt = now().Add(m.backoff)
	}
	m.want, m.outcome = wantKey, r
	return r, nil
}

func applyEach(ctx context.Context, exec Exec, call Caller, d kic.Driver, want Desired, lastGood *kic.State, last string, m *Memory, maxTests int) (EachResult, error) {
	if m.verdicts == nil {
		m.verdicts = map[string]string{}
	}
	v := m.verdicts
	out := EachResult{LeftOut: map[string]string{}}
	out.Hash = last
	maps.Copy(out.LeftOut, want.Refused) // refused by Desire: never in the state
	base, by := split(want.State)
	baseKey, allKey := hashOf(base.Options), hashOf(want)
	// A verdict on an Ingress alone stands while it and the options do; one given only with the
	// others (or not tested alone) while the whole desired state does.
	keyOf := func(who string) string { return who + "@" + hashOf(by[who]) + "@" + baseKey }
	withOthers := func(who string) string { return keyOf(who) + "@" + allKey }
	{ // keep only the verdicts that still apply
		live := map[string]bool{}
		for who := range by {
			live[keyOf(who)], live[withOthers(who)] = true, true
		}
		maps.DeleteFunc(v, func(k, _ string) bool { return !live[k] })
	}

	// The class's own part first: if even that can't go out, the class is held.
	if err := kic.Validate(d, base); err != nil {
		out.Held = err.Error()
		return out, nil
	}
	p0, err := d.Render(base)
	if err != nil {
		out.Held = "render: " + err.Error()
		return out, nil
	}
	testable := len(p0.Check) > 0 && p0.Config.Path != ""

	// What the proxy serves now.
	unknown := ""
	if lastGood == nil {
		lastGood = m.served
	}
	if lastGood == nil {
		if exec == nil {
			return out, fmt.Errorf("no way to read the controller silo's record")
		}
		lg, inRecord, why, err := readRecord(ctx, exec, d, p0)
		if err != nil {
			return out, fmt.Errorf("the record of what was applied: %w", err)
		}
		lastGood, unknown, m.served = lg, why, lg
		if inRecord {
			m.recorded = hashOf(*lg)
		}
	}
	var before map[string]fragment
	if lastGood != nil {
		_, before = split(*lastGood)
	}
	all := slices.Sorted(maps.Keys(by))
	for who := range want.Refused {
		if _, ok := by[who]; !ok {
			all = append(all, who)
		}
	}
	slices.Sort(all)

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
	// running: who's version here is one the proxy serves now. Unknown: any may be.
	running := func(who string) bool {
		if unknown != "" {
			return true
		}
		f, ok := before[who]
		cur, has := by[who]
		return ok && has && hashOf(f) == hashOf(cur)
	}
	changed := func(who string) bool {
		f, ok := before[who]
		return lastGood == nil || !ok || hashOf(f) != hashOf(by[who])
	}
	// hold puts who's last good version back in place of its refused change, so only the change
	// is held back and what it served keeps being served; false: it has none to go back to, or
	// another Ingress now holds one of that version's hosts and paths (Desire gave it away when
	// who changed). Either way who's reason is put in LeftOut.
	hold := func(who, why string) bool {
		out.LeftOut[who] = why
		f, ok := before[who]
		if cur, has := by[who]; unknown != "" || !ok || (has && hashOf(cur) == hashOf(f)) {
			return false
		}
		claims := map[string]string{}
		for w, g := range by {
			if w == who {
				continue
			}
			for _, r := range g.Routes {
				claims[r.Host+" "+r.Path] = w
			}
			for _, c := range g.Certificates {
				claims["certificate "+c.Name] = w
			}
		}
		for _, r := range f.Routes {
			if w, taken := claims[r.Host+" "+r.Path]; taken {
				out.LeftOut[who] = why + "; its last good version isn't served instead: " + w + " now has " + r.Host + r.Path
				return false
			}
		}
		f.Certificates = slices.DeleteFunc(slices.Clone(f.Certificates), func(c kic.Certificate) bool { // another one serves it now
			_, taken := claims["certificate "+c.Name]
			return taken
		})
		if alone(f) != nil {
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

	// Each Ingress against the driver alone (no proxy needed), and what the proxy said before
	// (never of one it serves now: that one is tested again).
	var keep []string
	for _, who := range slices.Sorted(maps.Keys(by)) {
		why := ""
		if err := alone(by[who]); err != nil {
			why = err.Error()
		} else if !running(who) {
			if w, ok := v[keyOf(who)]; ok {
				why, out.retry = w, true
			} else if w, ok := v[withOthers(who)]; ok {
				why, out.retry = w, true
			}
		}
		if why != "" && !hold(who, why) {
			continue
		}
		keep = append(keep, who)
	}

	// lost are the Ingresses the proxy (may) serve now that a configuration of only who would
	// remove although they didn't change. Never applied: the class is held instead.
	lost := func(who []string) []string {
		var l []string
		for _, w := range all {
			if !slices.Contains(who, w) && running(w) {
				l = append(l, w)
			}
		}
		return l
	}
	holdFor := func(l []string) error {
		out.retry = true
		if unknown != "" {
			out.Held = "the proxy's configuration stays and nothing new is applied until every Ingress of the class can be: the agent can't tell what the proxy serves now (" + unknown + ")"
		} else {
			out.Held = "the proxy's configuration stays and nothing new is applied: the proxy refuses, or couldn't be asked about, Ingresses it serves now that didn't change: " + strings.Join(l, ", ")
		}
		return errHold
	}
	// verdict remembers why the proxy refused who: alone, if a test of it alone says so.
	verdict := func(who, why string) {
		key := withOthers(who)
		if testable && out.Tests < maxTests-1 {
			if p, err := d.Render(join(base, by, []string{who})); err == nil {
				out.Tests++
				if w, err := Test(ctx, exec, p); err == nil && w != "" {
					key = keyOf(who)
				}
			}
		}
		v[key] = why
	}
	// refuse holds back who: remember, the proxy refused it (a verdict, see above); back, its last
	// good version may take its place.
	refuse := func(who []string, why string, remember, back bool) {
		out.retry = true
		var gone []string
		for _, w := range who {
			if remember {
				verdict(w, why)
			}
			if back {
				if hold(w, why) {
					continue
				}
			} else {
				out.LeftOut[w] = why
			}
			gone = append(gone, w)
		}
		keep = slices.DeleteFunc(keep, func(w string) bool { return slices.Contains(gone, w) })
	}

	// put applies st (rendered as p) and keeps the silo's record of it (record.go).
	recPath := RecordPath(p0)
	put := func(st kic.State, p kic.Plan) (Result, error) {
		h, staged := hashOf(st), false
		if m.recorded != h {
			b, _ := json.Marshal(record{Driver: d.Info().Name, State: st})
			if code, o, err := exec(ctx, WriteCmd(recPath+".next", "0600"), b); err != nil || code != 0 {
				out.RecordProblem = fmt.Sprintf("write %s.next: exit %d: %s %v", recPath, code, tail(o), err)
			} else {
				staged = true
			}
		}
		r, err := Apply(ctx, exec, call, d, p, last)
		if err != nil {
			return r, err // RECORD.next stays: a restart checks it against what the proxy has
		}
		if r.Rejected != "" {
			if staged {
				_, _, _ = exec(ctx, RemoveCmd(recPath+".next"), nil)
			}
			return r, nil
		}
		s := st
		m.served = &s
		if staged {
			if code, o, err := exec(ctx, MoveCmd(recPath+".next", recPath), nil); err != nil || code != 0 {
				out.RecordProblem = fmt.Sprintf("move %s.next: exit %d: %s %v", recPath, code, tail(o), err)
			} else {
				m.recorded = h
			}
		}
		return r, nil
	}
	// try applies base with keep; it's a test too (the proxy checks before it loads anything).
	try := func() (Result, kic.Plan, error) {
		if l := lost(keep); len(l) > 0 {
			return Result{Hash: last}, kic.Plan{}, holdFor(l)
		}
		st := join(base, by, keep)
		p, err := d.Render(st)
		if err != nil {
			return Result{Hash: last, Rejected: "render: " + err.Error()}, p, nil
		}
		out.Tests++
		r, err := put(st, p)
		if err == nil && r.Rejected == "" {
			out.Served = st
		}
		return r, p, err
	}
	res, _, err := try()
	if err != nil || res.Rejected == "" {
		out.Result = res
		return out, err
	}

	// The proxy refused it. Its blame first (only of what changed): those are out, the rest goes again.
	blamed := slices.DeleteFunc(intersect(res.Blamed, keep), func(w string) bool { return !changed(w) })
	if len(blamed) > 0 && out.Tests < maxTests-1 {
		refuse(blamed, "the proxy refused the configuration with it: "+res.Rejected, true, true)
		if res, _, err = try(); err != nil || res.Rejected == "" {
			out.Result = res
			return out, err
		}
	}

	var suspects, trusted []string
	for _, w := range keep {
		if changed(w) {
			suspects = append(suspects, w)
		} else {
			trusted = append(trusted, w)
		}
	}
	// sideTest is a config test, run on the side: the running proxy never sees it. ok=false: the
	// bound was reached (one run is kept for the apply after), or it couldn't be run.
	sideTest := func(who []string) (string, bool) {
		if out.Tests >= maxTests-1 {
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
	// An admin API's only test is the apply: never while what the proxy serves is unknown.
	if len(suspects) > 0 && (testable || (p0.Reload.Call != nil && unknown == "")) {
		changedLive := false
		var test func(who []string) (string, bool)
		ctxSet := trusted
		if testable {
			test = sideTest
			// What served before still passes? Then only the changed ones can be at fault.
			if why, ok := test(trusted); ok && why != "" {
				suspects, ctxSet = keep, nil // what passed before fails now: everything is suspect
			}
		} else {
			// An admin API: its only test is the apply. Applying what served before plus some of
			// the changed Ingresses never drops a route that worked, so a part it accepts stays
			// applied, and the context grows with it.
			test = func(who []string) (string, bool) {
				if out.Tests >= maxTests-1 || len(lost(who)) > 0 {
					return "", false
				}
				st := join(base, by, who)
				p, err := d.Render(st)
				if err != nil {
					return "render: " + err.Error(), true
				}
				out.Tests++
				r, err := put(st, p)
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
		bad, unchecked := bisect(suspects, func(sub []string) (string, bool) {
			return test(append(slices.Clone(ctxSet), sub...))
		})
		for _, b := range bad {
			refuse([]string{b.who}, "the proxy refused it: "+b.why, true, true)
		}
		if len(unchecked) > 0 {
			// Not remembered: they are tried again on the next pass.
			out.unchecked = true
			refuse(unchecked, fmt.Sprintf("not checked yet: finding the Ingress the proxy refuses took more than %d test runs", maxTests), false, true)
		}
		if res, _, err = try(); err != nil || res.Rejected == "" {
			res.Changed = res.Changed || changedLive
			out.Result = res
			return out, err
		}
	}

	// Still refused: Ingresses fine alone (and in halves) but not together. With a config test,
	// they are added one by one to what passes; the one that makes it fail is held back.
	if left := intersect(suspects, keep); len(left) > 0 && testable {
		ctxSet := slices.DeleteFunc(slices.Clone(keep), func(w string) bool { return slices.Contains(left, w) })
		for i, w := range left {
			why, ok := sideTest(append(slices.Clone(ctxSet), w))
			if !ok {
				out.unchecked = true
				refuse(left[i:], fmt.Sprintf("not checked yet: finding the Ingress the proxy refuses took more than %d test runs", maxTests), false, true)
				break
			}
			if why != "" {
				refuse([]string{w}, "the proxy refused it with the class's other Ingresses: "+why, true, true)
				continue
			}
			ctxSet = append(ctxSet, w)
		}
		if res, _, err = try(); err != nil || res.Rejected == "" {
			out.Result = res
			return out, err
		}
	}
	// Still refused (an admin-API driver that couldn't tell): fall back to what was served
	// before, leaving out everything that changed.
	if unknown != "" {
		out.Result = res
		return out, holdFor(nil)
	}
	if left := intersect(suspects, keep); len(left) > 0 {
		refuse(left, "the proxy refused the configuration with the Ingresses changed since the last good one, and couldn't say which: "+res.Rejected, false, true)
		if res, _, err = try(); err != nil || res.Rejected == "" {
			out.Result = res
			return out, err
		}
	}
	// Then the class's own part alone, unless that would remove what the proxy serves: if the
	// proxy refuses even that, the class is held.
	if l := lost(nil); len(l) > 0 {
		out.Result = res
		return out, holdFor(l)
	}
	refuse(slices.Clone(keep), "the proxy refused every configuration with it: "+res.Rejected, false, false)
	if res, _, err = try(); err != nil || res.Rejected == "" {
		out.Result = res
		return out, err
	}
	out.Held = "the proxy refuses even the class's own part: " + res.Rejected
	for w := range by { // nothing is applied: none of these is "refused" for what it is
		delete(v, keyOf(w))
		delete(v, withOthers(w))
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

// ForgetMemory drops the Memory MemoryOf keeps for uid: what a kevasod that restarts has (tests).
func ForgetMemory(uid string) {
	memMu.Lock()
	defer memMu.Unlock()
	delete(memories, uid)
}
