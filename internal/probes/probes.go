// Package probes decides a silo's probes (design §0.6). Pure: given the probes, their last
// results and the clock, it says which probe is due, what one run's result does to its state
// (results in a row flip the answer, so one bad run doesn't), the silo's conditions (Started,
// StartFailed, Ready, and liveness's part of Degraded), and what a liveness failure does.
//
// Startup gates the other two: until it passes they're Disabled. Past its deadline the silo is
// StartFailed and stays up for debugging; startup keeps running, and passing late still starts it.
// A probe that can't run at all (the runtime can't exec, the port isn't a service port, the silo
// has no address its host reaches) is CantRun: its own reason, never counted as a failure.
//
// The host's agent runs the probes (internal/agent/probes.go) and keeps the result in
// status.probes; nothing here touches the network or the runtime.
package probes

import (
	"fmt"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Defaults.
const (
	DefaultPeriod    = 10 * time.Second
	DefaultTimeout   = 5 * time.Second // one run's limit
	DefaultDeadline  = 5 * time.Minute // startup's overall deadline
	DefaultSuccesses = 1
	DefaultFailures  = 3
)

// Restart backoff for liveness onFailure: restart.
const (
	FirstBackoff = 10 * time.Second
	MaxBackoff   = 5 * time.Minute
	// StableAfter: a silo that stays up this long after a restart starts its backoff over.
	StableAfter = 10 * time.Minute
)

func dur(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// Period is how often p runs.
func Period(p *v1.Probe) time.Duration { return dur(p.Period, DefaultPeriod) }

// RunTimeout is one run's limit. A startup probe's timeout is its deadline, so its runs get the
// default limit, or the period if that's shorter.
func RunTimeout(name string, p *v1.Probe) time.Duration {
	if name == v1.ProbeStartup {
		return min(DefaultTimeout, Period(p))
	}
	return dur(p.Timeout, DefaultTimeout)
}

// Deadline is a startup probe's overall deadline.
func Deadline(p *v1.Probe) time.Duration { return dur(p.Timeout, DefaultDeadline) }

func successes(p *v1.Probe) int {
	if p.Successes > 0 {
		return p.Successes
	}
	return DefaultSuccesses
}

func failures(p *v1.Probe) int {
	if p.Failures > 0 {
		return p.Failures
	}
	return DefaultFailures
}

// OnFailure is a liveness probe's onFailure, report by default.
func OnFailure(p *v1.Probe) string {
	if p != nil && p.OnFailure == v1.OnFailureRestart {
		return v1.OnFailureRestart
	}
	return v1.OnFailureReport
}

// Named is one of a spec's probes with its name.
type Named struct {
	Name  string
	Probe *v1.Probe
}

// List is a spec's probes in order (startup, readiness, liveness), the ones it has.
func List(spec *v1.Probes) []Named {
	if spec == nil {
		return nil
	}
	var out []Named
	for _, n := range []Named{{v1.ProbeStartup, spec.Startup}, {v1.ProbeReadiness, spec.Readiness}, {v1.ProbeLiveness, spec.Liveness}} {
		if n.Probe != nil {
			out = append(out, n)
		}
	}
	return out
}

// Outcome is one run of a probe.
type Outcome struct {
	Result string // v1.ResultSuccess | ResultFailure | ResultCantRun
	Reason string // short: the end of the output, the HTTP status, the dial error
}

func at(t time.Time) *time.Time { return &t }

// Record applies one run's outcome to a probe's status. Results in a row flip it: Successes make it
// Passing, Failures make it Failing; anything between leaves it as it was. CantRun is its own
// state at once (nothing ran, so there's nothing to damp). A startup probe never fails by count:
// only its deadline makes it Failing (Normalize).
func Record(name string, p *v1.Probe, prev v1.ProbeStatus, o Outcome, now time.Time) v1.ProbeStatus {
	st := prev
	st.Name, st.LastResult, st.LastTime, st.Reason = name, o.Result, at(now), o.Reason
	state := st.State
	switch o.Result {
	case v1.ResultSuccess:
		st.Successes, st.Failures = st.Successes+1, 0
		if st.Successes >= successes(p) {
			state = v1.ProbePassing
		} else if state == v1.ProbeCantRun {
			state = v1.ProbePending
		}
	case v1.ResultFailure:
		st.Successes, st.Failures = 0, st.Failures+1
		switch {
		case name != v1.ProbeStartup && st.Failures >= failures(p):
			state = v1.ProbeFailing
		case state == v1.ProbeCantRun:
			state = v1.ProbePending
		}
	default:
		st.Successes, st.Failures, state = 0, 0, v1.ProbeCantRun
	}
	if state != st.State || st.Since == nil {
		st.State, st.Since = state, at(now)
	}
	return st
}

// Normalize makes the statuses fit the spec at now: one per probe, in order; readiness and
// liveness Disabled until startup passes (and Pending, from scratch, once it has); startup
// Failing once its deadline has passed since startedAt (when the silo's workload started).
func Normalize(spec *v1.Probes, prev []v1.ProbeStatus, startedAt, now time.Time) []v1.ProbeStatus {
	var out []v1.ProbeStatus
	started := spec == nil || spec.Startup == nil
	for _, np := range List(spec) {
		st := v1.ProbeStatus{Name: np.Name, State: v1.ProbePending, Since: at(now)}
		if p := v1.FindProbe(prev, np.Name); p != nil {
			st = *p
		}
		switch np.Name {
		case v1.ProbeStartup:
			if st.State == v1.ProbeDisabled {
				st.State = v1.ProbePending
			}
			if st.State == v1.ProbePending && !startedAt.IsZero() && !now.Before(startedAt.Add(Deadline(np.Probe))) {
				st.State, st.Since = v1.ProbeFailing, at(startedAt.Add(Deadline(np.Probe)))
				st.Reason = fmt.Sprintf("no pass within %s: %s", Deadline(np.Probe), st.Reason)
			}
			started = st.State == v1.ProbePassing
		default:
			switch {
			case !started && st.State != v1.ProbeDisabled:
				st = v1.ProbeStatus{Name: np.Name, State: v1.ProbeDisabled, Since: at(now), Reason: "waits for startup"}
			case started && st.State == v1.ProbeDisabled:
				st = v1.ProbeStatus{Name: np.Name, State: v1.ProbePending, Since: at(now)}
			}
		}
		out = append(out, st)
	}
	return out
}

// Due is which probes should run at now, and how long until the next one is due (or startup's
// deadline comes): 0 if nothing will be.
func Due(spec *v1.Probes, st []v1.ProbeStatus, startedAt, now time.Time) (due []string, next time.Duration) {
	soonest := func(d time.Duration) {
		if d > 0 && (next == 0 || d < next) {
			next = d
		}
	}
	for _, np := range List(spec) {
		s := v1.FindProbe(st, np.Name)
		if s == nil || s.State == v1.ProbeDisabled || (np.Name == v1.ProbeStartup && s.State == v1.ProbePassing) {
			continue
		}
		period := Period(np.Probe)
		if s.LastTime == nil || !now.Before(s.LastTime.Add(period)) {
			due = append(due, np.Name)
			soonest(period)
		} else {
			soonest(s.LastTime.Add(period).Sub(now))
		}
		if np.Name == v1.ProbeStartup && s.State == v1.ProbePending && !startedAt.IsZero() {
			soonest(startedAt.Add(Deadline(np.Probe)).Sub(now))
		}
	}
	return due, next
}

// Condition is one condition the probes decide.
type Condition struct {
	Type    string
	Status  meta.ConditionStatus
	Reason  string
	Message string
}

func why(s *v1.ProbeStatus) string {
	if s.Reason == "" {
		return ""
	}
	return ": " + s.Reason
}

// Conditions are Started, Ready and (with a startup probe) StartFailed, for a silo that runs
// with its init done. Without probes: Started and Ready, as soon as it runs.
func Conditions(spec *v1.Probes, st []v1.ProbeStatus) []Condition {
	var out []Condition
	started := Condition{Type: "Started", Status: meta.ConditionTrue, Reason: "Running", Message: "running"}
	if spec != nil && spec.Startup != nil {
		s := v1.FindProbe(st, v1.ProbeStartup)
		if s == nil {
			s = &v1.ProbeStatus{State: v1.ProbePending}
		}
		failed := Condition{Type: "StartFailed", Status: meta.ConditionFalse, Reason: "NotFailed", Message: "startup probe hasn't run out of time"}
		switch s.State {
		case v1.ProbePassing:
			started = Condition{"Started", meta.ConditionTrue, "StartupPassed", "startup probe passed"}
		case v1.ProbeFailing:
			started = Condition{"Started", meta.ConditionFalse, "StartupTimedOut", "startup probe" + why(s) + " (the silo stays up for debugging)"}
			failed = Condition{"StartFailed", meta.ConditionTrue, "StartupTimedOut", "startup probe" + why(s)}
		case v1.ProbeCantRun:
			started = Condition{"Started", meta.ConditionFalse, "StartupCantRun", "startup probe can't run" + why(s)}
		default:
			started = Condition{"Started", meta.ConditionFalse, "Starting", "waiting for the startup probe" + why(s)}
		}
		out = append(out, started, failed)
	} else {
		out = append(out, started)
	}
	ready := Condition{Type: "Ready", Status: meta.ConditionTrue, Reason: "Running", Message: "running"}
	switch {
	case started.Status != meta.ConditionTrue:
		ready = Condition{"Ready", meta.ConditionFalse, "NotStarted", started.Message}
	case spec != nil && spec.Readiness != nil:
		s := v1.FindProbe(st, v1.ProbeReadiness)
		if s == nil {
			s = &v1.ProbeStatus{State: v1.ProbePending}
		}
		switch s.State {
		case v1.ProbePassing:
			ready = Condition{"Ready", meta.ConditionTrue, "ReadinessPassing", "running, readiness passing"}
		case v1.ProbeFailing:
			ready = Condition{"Ready", meta.ConditionFalse, "NotReady", "readiness failing" + why(s)}
		case v1.ProbeCantRun:
			ready = Condition{"Ready", meta.ConditionFalse, "ReadinessCantRun", "readiness probe can't run" + why(s)}
		default:
			ready = Condition{"Ready", meta.ConditionFalse, "NotReady", "readiness hasn't passed yet" + why(s)}
		}
	}
	return append(out, ready)
}

// Degraded is liveness's part of the Degraded condition: true while it's failing (whatever
// onFailure says: report marks Degraded and nothing else; restart also restarts).
func Degraded(spec *v1.Probes, st []v1.ProbeStatus) (bool, string) {
	if spec == nil || spec.Liveness == nil {
		return false, ""
	}
	s := v1.FindProbe(st, v1.ProbeLiveness)
	if s == nil || s.State != v1.ProbeFailing {
		return false, ""
	}
	return true, "liveness failing" + why(s)
}

// Backoff is the wait before restart number n+1 in a row (n restarts in a row so far).
func Backoff(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	d := FirstBackoff
	for i := 1; i < n && d < MaxBackoff; i++ {
		d *= 2
	}
	return min(d, MaxBackoff)
}

// OnLiveness says what a liveness failure does now: restart (only with onFailure: restart, never
// by default), or wait this long first (the backoff since the last restart).
func OnLiveness(spec *v1.Probes, st []v1.ProbeStatus, r *v1.LivenessRestarts, now time.Time) (restart bool, wait time.Duration) {
	if spec == nil || OnFailure(spec.Liveness) != v1.OnFailureRestart {
		return false, 0
	}
	if bad, _ := Degraded(spec, st); !bad {
		return false, 0
	}
	if r == nil || r.Last == nil {
		return true, 0
	}
	n := r.Backoff
	if !now.Before(r.Last.Add(StableAfter)) {
		n = 0 // it stayed up long enough: this one isn't "in a row"
	}
	if w := r.Last.Add(Backoff(n)).Sub(now); w > 0 {
		return false, w
	}
	return true, 0
}

// Restarted is the restart record after a liveness restart at now.
func Restarted(r *v1.LivenessRestarts, now time.Time) *v1.LivenessRestarts {
	next := v1.LivenessRestarts{Count: 1, Backoff: 1, Last: at(now)}
	if r != nil {
		next.Count = r.Count + 1
		if r.Last != nil && now.Before(r.Last.Add(StableAfter)) {
			next.Backoff = r.Backoff + 1
		}
	}
	return &next
}
