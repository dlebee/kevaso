package probes_test

import (
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/probes"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func ok(why string) probes.Outcome   { return probes.Outcome{Result: v1.ResultSuccess, Reason: why} }
func bad(why string) probes.Outcome  { return probes.Outcome{Result: v1.ResultFailure, Reason: why} }
func cant(why string) probes.Outcome { return probes.Outcome{Result: v1.ResultCantRun, Reason: why} }

// Results in a row flip the answer: thresholds damp flapping.
func TestRecord(t *testing.T) {
	p := &v1.Probe{Successes: 2, Failures: 3}
	for _, tc := range []struct {
		name  string
		probe string
		runs  []probes.Outcome
		want  string
	}{
		{"one success isn't enough", v1.ProbeReadiness, []probes.Outcome{ok("")}, v1.ProbePending},
		{"two in a row pass", v1.ProbeReadiness, []probes.Outcome{ok(""), ok("")}, v1.ProbePassing},
		{"a failure between starts over", v1.ProbeReadiness, []probes.Outcome{ok(""), bad("x"), ok("")}, v1.ProbePending},
		{"passing survives two failures", v1.ProbeReadiness, []probes.Outcome{ok(""), ok(""), bad("x"), bad("x")}, v1.ProbePassing},
		{"three in a row fail it", v1.ProbeReadiness, []probes.Outcome{ok(""), ok(""), bad("x"), bad("x"), bad("x")}, v1.ProbeFailing},
		{"failing needs two passes back", v1.ProbeReadiness, []probes.Outcome{bad(""), bad(""), bad(""), ok("")}, v1.ProbeFailing},
		{"and gets them", v1.ProbeReadiness, []probes.Outcome{bad(""), bad(""), bad(""), ok(""), ok("")}, v1.ProbePassing},
		{"flapping never flips it", v1.ProbeReadiness, []probes.Outcome{ok(""), ok(""), bad(""), ok(""), bad(""), bad(""), ok(""), bad("")}, v1.ProbePassing},
		{"can't run is its own state at once", v1.ProbeReadiness, []probes.Outcome{ok(""), ok(""), cant("no exec")}, v1.ProbeCantRun},
		{"can't run isn't a failure", v1.ProbeLiveness, []probes.Outcome{cant("x"), cant("x"), cant("x"), cant("x")}, v1.ProbeCantRun},
		{"from can't run, a result is pending again", v1.ProbeReadiness, []probes.Outcome{cant("x"), bad("y")}, v1.ProbePending},
		{"startup never fails by count", v1.ProbeStartup, []probes.Outcome{bad(""), bad(""), bad(""), bad(""), bad("")}, v1.ProbePending},
		{"startup passes", v1.ProbeStartup, []probes.Outcome{bad(""), ok(""), ok("")}, v1.ProbePassing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := v1.ProbeStatus{Name: tc.probe, State: v1.ProbePending}
			now := t0
			for _, o := range tc.runs {
				now = now.Add(time.Second)
				st = probes.Record(tc.probe, p, st, o, now)
			}
			if st.State != tc.want {
				t.Fatalf("state %s, want %s (%+v)", st.State, tc.want, st)
			}
			if st.LastTime == nil || !st.LastTime.Equal(now) || st.LastResult != tc.runs[len(tc.runs)-1].Result {
				t.Fatalf("last run not recorded: %+v", st)
			}
		})
	}
	// Since moves only when the state does.
	st := probes.Record("readiness", p, v1.ProbeStatus{Name: "readiness", State: v1.ProbePending}, ok(""), t0)
	st = probes.Record("readiness", p, st, ok(""), t0.Add(time.Second))
	since := *st.Since
	st = probes.Record("readiness", p, st, bad("x"), t0.Add(2*time.Second))
	if !st.Since.Equal(since) || !since.Equal(t0.Add(time.Second)) {
		t.Fatalf("since %v, want %v", st.Since, since)
	}
	if st.Reason != "x" {
		t.Fatalf("reason %q", st.Reason)
	}
}

func spec(startup, readiness, liveness bool) *v1.Probes {
	ps := &v1.Probes{}
	if startup {
		ps.Startup = &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}, Period: "5s", Timeout: "1m"}
	}
	if readiness {
		ps.Readiness = &v1.Probe{HTTP: &v1.HTTPProbe{Port: "rpc"}, Period: "10s"}
	}
	if liveness {
		ps.Liveness = &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"true"}}, Period: "30s", Failures: 2}
	}
	return ps
}

// Startup gates the other two; its deadline makes it Failing.
func TestNormalize(t *testing.T) {
	sp := spec(true, true, true)
	st := probes.Normalize(sp, nil, t0, t0)
	if len(st) != 3 || st[0].State != v1.ProbePending || st[1].State != v1.ProbeDisabled || st[2].State != v1.ProbeDisabled {
		t.Fatalf("fresh: %+v", st)
	}
	// Startup passes: the others start from scratch.
	st[0] = probes.Record("startup", sp.Startup, st[0], ok(""), t0.Add(5*time.Second))
	st = probes.Normalize(sp, st, t0, t0.Add(5*time.Second))
	if st[1].State != v1.ProbePending || st[2].State != v1.ProbePending {
		t.Fatalf("after startup: %+v", st)
	}
	// Past the deadline with no pass: Failing, since the deadline itself.
	st = probes.Normalize(sp, nil, t0, t0.Add(59*time.Second))
	if st[0].State != v1.ProbePending {
		t.Fatalf("before the deadline: %+v", st[0])
	}
	st[0].Reason = "connection refused"
	st = probes.Normalize(sp, st, t0, t0.Add(61*time.Second))
	if st[0].State != v1.ProbeFailing || !st[0].Since.Equal(t0.Add(time.Minute)) || !strings.Contains(st[0].Reason, "connection refused") {
		t.Fatalf("past the deadline: %+v", st[0])
	}
	if st[1].State != v1.ProbeDisabled {
		t.Fatal("readiness ran without startup")
	}
	// Passing late still starts it.
	st[0] = probes.Record("startup", sp.Startup, st[0], ok(""), t0.Add(2*time.Minute))
	st = probes.Normalize(sp, st, t0, t0.Add(2*time.Minute))
	if st[0].State != v1.ProbePassing || st[1].State != v1.ProbePending {
		t.Fatalf("late pass: %+v", st)
	}
	// A can't-run startup isn't failed by the deadline: it never got to try.
	st = probes.Normalize(sp, []v1.ProbeStatus{{Name: "startup", State: v1.ProbeCantRun}}, t0, t0.Add(time.Hour))
	if st[0].State != v1.ProbeCantRun {
		t.Fatalf("can't run: %+v", st[0])
	}
	// No startup probe: the others run at once; a probe taken out of the spec goes.
	st = probes.Normalize(spec(false, true, false), []v1.ProbeStatus{{Name: "liveness", State: v1.ProbeFailing}}, t0, t0)
	if len(st) != 1 || st[0].Name != "readiness" || st[0].State != v1.ProbePending {
		t.Fatalf("no startup: %+v", st)
	}
	if probes.Normalize(nil, []v1.ProbeStatus{{Name: "readiness"}}, t0, t0) != nil {
		t.Fatal("no probes: no statuses")
	}
}

func TestDue(t *testing.T) {
	sp := spec(true, true, true)
	at := func(d time.Duration) *time.Time { x := t0.Add(d); return &x }
	for _, tc := range []struct {
		name string
		st   []v1.ProbeStatus
		now  time.Duration
		due  []string
		next time.Duration
	}{
		{"startup first, never run", []v1.ProbeStatus{{Name: "startup", State: v1.ProbePending}, {Name: "readiness", State: v1.ProbeDisabled}, {Name: "liveness", State: v1.ProbeDisabled}},
			0, []string{"startup"}, 5 * time.Second},
		{"startup ran 2s ago", []v1.ProbeStatus{{Name: "startup", State: v1.ProbePending, LastTime: at(0)}, {Name: "readiness", State: v1.ProbeDisabled}},
			2 * time.Second, nil, 3 * time.Second},
		{"the deadline comes before the next run", []v1.ProbeStatus{{Name: "startup", State: v1.ProbePending, LastTime: at(58 * time.Second)}},
			58 * time.Second, nil, 2 * time.Second},
		{"startup passed: the others", []v1.ProbeStatus{{Name: "startup", State: v1.ProbePassing, LastTime: at(0)}, {Name: "readiness", State: v1.ProbePending}, {Name: "liveness", State: v1.ProbePending, LastTime: at(0)}},
			10 * time.Second, []string{"readiness"}, 10 * time.Second},
		{"both due", []v1.ProbeStatus{{Name: "startup", State: v1.ProbePassing}, {Name: "readiness", State: v1.ProbePassing, LastTime: at(0)}, {Name: "liveness", State: v1.ProbePassing, LastTime: at(0)}},
			30 * time.Second, []string{"readiness", "liveness"}, 10 * time.Second},
		{"startup failed keeps trying", []v1.ProbeStatus{{Name: "startup", State: v1.ProbeFailing, LastTime: at(0)}},
			5 * time.Second, []string{"startup"}, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			due, next := probes.Due(sp, tc.st, t0, t0.Add(tc.now))
			if strings.Join(due, ",") != strings.Join(tc.due, ",") || next != tc.next {
				t.Fatalf("due %v next %v, want %v %v", due, next, tc.due, tc.next)
			}
		})
	}
	if due, next := probes.Due(nil, nil, t0, t0); due != nil || next != 0 {
		t.Fatal("no probes: nothing due")
	}
}

func TestConditions(t *testing.T) {
	cond := func(cs []probes.Condition, typ string) *probes.Condition {
		for i := range cs {
			if cs[i].Type == typ {
				return &cs[i]
			}
		}
		return nil
	}
	for _, tc := range []struct {
		name                   string
		spec                   *v1.Probes
		st                     []v1.ProbeStatus
		started, ready, failed string // True | False | "" (absent); reason after ':'
	}{
		{"no probes: started and ready as it runs", nil, nil, "True:Running", "True:Running", ""},
		{"starting", spec(true, true, false), []v1.ProbeStatus{{Name: "startup", State: v1.ProbePending}}, "False:Starting", "False:NotStarted", "False:NotFailed"},
		{"start failed", spec(true, true, false), []v1.ProbeStatus{{Name: "startup", State: v1.ProbeFailing}}, "False:StartupTimedOut", "False:NotStarted", "True:StartupTimedOut"},
		{"startup can't run", spec(true, false, false), []v1.ProbeStatus{{Name: "startup", State: v1.ProbeCantRun}}, "False:StartupCantRun", "False:NotStarted", "False:NotFailed"},
		{"started, not ready yet", spec(true, true, false), []v1.ProbeStatus{{Name: "startup", State: v1.ProbePassing}, {Name: "readiness", State: v1.ProbePending}}, "True:StartupPassed", "False:NotReady", "False:NotFailed"},
		{"ready", spec(false, true, false), []v1.ProbeStatus{{Name: "readiness", State: v1.ProbePassing}}, "True:Running", "True:ReadinessPassing", ""},
		{"not ready", spec(false, true, false), []v1.ProbeStatus{{Name: "readiness", State: v1.ProbeFailing, Reason: "HTTP 503"}}, "True:Running", "False:NotReady", ""},
		{"readiness can't run: its own reason", spec(false, true, false), []v1.ProbeStatus{{Name: "readiness", State: v1.ProbeCantRun}}, "True:Running", "False:ReadinessCantRun", ""},
		{"liveness alone doesn't touch Ready", spec(false, false, true), []v1.ProbeStatus{{Name: "liveness", State: v1.ProbeFailing}}, "True:Running", "True:Running", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := probes.Conditions(tc.spec, tc.st)
			for typ, want := range map[string]string{"Started": tc.started, "Ready": tc.ready, "StartFailed": tc.failed} {
				c := cond(cs, typ)
				got := ""
				if c != nil {
					got = string(c.Status) + ":" + c.Reason
				}
				if got != want {
					t.Errorf("%s: %s, want %s", typ, got, want)
				}
			}
		})
	}
	if c := cond(probes.Conditions(spec(false, true, false), []v1.ProbeStatus{{Name: "readiness", State: v1.ProbeFailing, Reason: "HTTP 503"}}), "Ready"); !strings.Contains(c.Message, "HTTP 503") {
		t.Fatalf("message: %q", c.Message)
	}
	if c := cond(probes.Conditions(nil, nil), "Ready"); c.Status != meta.ConditionTrue {
		t.Fatal("a silo with no probes is Ready when it runs")
	}
}

// Liveness: report marks Degraded only; restart restarts, with a growing backoff; never by default.
func TestOnLiveness(t *testing.T) {
	failing := []v1.ProbeStatus{{Name: "liveness", State: v1.ProbeFailing, Reason: "exit 1"}}
	report, restart := spec(false, false, true), spec(false, false, true)
	restart.Liveness.OnFailure = v1.OnFailureRestart
	if d, msg := probes.Degraded(report, failing); !d || !strings.Contains(msg, "exit 1") {
		t.Fatalf("report: degraded %v %q", d, msg)
	}
	if r, _ := probes.OnLiveness(report, failing, nil, t0); r {
		t.Fatal("report restarted")
	}
	if d, _ := probes.Degraded(report, []v1.ProbeStatus{{Name: "liveness", State: v1.ProbeCantRun}}); d {
		t.Fatal("can't run made it Degraded")
	}
	if r, _ := probes.OnLiveness(restart, []v1.ProbeStatus{{Name: "liveness", State: v1.ProbePassing}}, nil, t0); r {
		t.Fatal("restarted a passing silo")
	}
	if r, w := probes.OnLiveness(restart, failing, nil, t0); !r || w != 0 {
		t.Fatal("the first restart waits")
	}
	var rec *v1.LivenessRestarts
	now := t0
	for i, want := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute} {
		rec = probes.Restarted(rec, now)
		if rec.Count != i+1 {
			t.Fatalf("count %d, want %d", rec.Count, i+1)
		}
		if r, w := probes.OnLiveness(restart, failing, rec, now.Add(time.Second)); r || w != want-time.Second {
			t.Fatalf("restart %d: again at once (%v), or waits %v, want %v", i+1, r, w, want-time.Second)
		}
		now = now.Add(want)
		if r, _ := probes.OnLiveness(restart, failing, rec, now); !r {
			t.Fatalf("restart %d: still waiting after %v", i+1, want)
		}
	}
	// Stayed up long enough: the backoff starts over.
	later := now.Add(probes.StableAfter)
	if r, w := probes.OnLiveness(restart, failing, rec, later); !r || w != 0 {
		t.Fatal("a stable silo still waits")
	}
	if rec = probes.Restarted(rec, later); rec.Backoff != 1 || rec.Count != 8 {
		t.Fatalf("after a stable stretch: %+v", rec)
	}
}

func TestValidate(t *testing.T) {
	svc := &v1.SiloService{Ports: []v1.ServicePort{{Port: "rpc"}}, RouteWhen: v1.RouteWhenReady}
	// metrics is declared but not on the service: a probe may still use it.
	good := v1.SiloSpec{Ports: []v1.SiloPort{{Name: "rpc", Port: 8545}, {Name: "metrics", Port: 9100}}, Service: svc, Probes: &v1.Probes{
		Startup:   &v1.Probe{TCP: &v1.TCPProbe{Port: "rpc"}, Timeout: "10m"},
		Readiness: &v1.Probe{HTTP: &v1.HTTPProbe{Port: "metrics", Path: "/health"}, Period: "10s"},
		Liveness:  &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"pg_isready"}}, Failures: 3, OnFailure: "restart"},
	}}
	if errs := probes.Validate(good); len(errs) != 0 {
		t.Fatalf("good: %v", errs)
	}
	if errs := probes.Validate(v1.SiloSpec{}); len(errs) != 0 {
		t.Fatalf("nothing at all is fine: %v", errs)
	}
	for _, tc := range []struct {
		name string
		edit func(*v1.SiloSpec)
		want string
	}{
		{"two kinds", func(s *v1.SiloSpec) { s.Probes.Readiness.Exec = &v1.ExecProbe{Command: []string{"x"}} }, "exactly one"},
		{"no kind", func(s *v1.SiloSpec) { s.Probes.Readiness.HTTP = nil }, "exactly one"},
		{"empty command", func(s *v1.SiloSpec) { s.Probes.Liveness.Exec.Command = nil }, "needs a command"},
		{"unknown port name", func(s *v1.SiloSpec) { s.Probes.Startup.TCP.Port = "web" }, `"web" isn't one of the silo's declared ports`},
		{"a number isn't a port's name", func(s *v1.SiloSpec) { s.Probes.Readiness.HTTP.Port = "8545" }, `"8545" isn't one of the silo's declared ports`},
		{"no port", func(s *v1.SiloSpec) { s.Probes.Startup.TCP.Port = "" }, "needed (a declared port's name"},
		{"relative path", func(s *v1.SiloSpec) { s.Probes.Readiness.HTTP.Path = "health" }, "must start with /"},
		{"bad period", func(s *v1.SiloSpec) { s.Probes.Readiness.Period = "often" }, "isn't a duration"},
		{"startup failures", func(s *v1.SiloSpec) { s.Probes.Startup.Failures = 2 }, "only by its deadline"},
		{"onFailure on readiness", func(s *v1.SiloSpec) { s.Probes.Readiness.OnFailure = "restart" }, "only liveness"},
		{"onFailure value", func(s *v1.SiloSpec) { s.Probes.Liveness.OnFailure = "kill" }, "report or restart"},
		{"routeWhen not stated with readiness", func(s *v1.SiloSpec) { svc := *s.Service; svc.RouteWhen = ""; s.Service = &svc }, "say whether traffic waits"},
		{"ready without readiness", func(s *v1.SiloSpec) { s.Probes.Readiness = nil }, "ready needs a readiness probe"},
		{"routeWhen value", func(s *v1.SiloSpec) { svc := *s.Service; svc.RouteWhen = "always"; s.Service = &svc }, "ready or running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := good
			p := *good.Probes
			st, rd, lv := *p.Startup, *p.Readiness, *p.Liveness
			tcp, http, ex := *st.TCP, *rd.HTTP, *lv.Exec
			st.TCP, rd.HTTP, lv.Exec = &tcp, &http, &ex
			p.Startup, p.Readiness, p.Liveness = &st, &rd, &lv
			s.Probes = &p
			tc.edit(&s)
			errs := strings.Join(probes.Validate(s), "; ")
			if !strings.Contains(errs, tc.want) {
				t.Fatalf("got %q, want %q", errs, tc.want)
			}
		})
	}
	// A readiness probe and no service: nothing to route, nothing to state.
	if errs := probes.Validate(v1.SiloSpec{Probes: &v1.Probes{Readiness: &v1.Probe{Exec: &v1.ExecProbe{Command: []string{"x"}}}}}); len(errs) != 0 {
		t.Fatalf("no service: %v", errs)
	}
	// running with a readiness probe is a statement too.
	s := good
	s.Service = &v1.SiloService{Ports: svc.Ports, RouteWhen: v1.RouteWhenRunning}
	if errs := probes.Validate(s); len(errs) != 0 {
		t.Fatalf("running stated: %v", errs)
	}
}

func TestTimeouts(t *testing.T) {
	p := &v1.Probe{Period: "2s", Timeout: "10m"}
	if probes.RunTimeout("startup", p) != 2*time.Second || probes.Deadline(p) != 10*time.Minute {
		t.Fatal("startup: the timeout is the deadline; each run gets the default or the period")
	}
	if probes.RunTimeout("readiness", &v1.Probe{Timeout: "1s"}) != time.Second || probes.RunTimeout("readiness", &v1.Probe{}) != probes.DefaultTimeout {
		t.Fatal("readiness: the timeout is each run's")
	}
	if probes.Period(&v1.Probe{}) != probes.DefaultPeriod || probes.Deadline(&v1.Probe{}) != probes.DefaultDeadline {
		t.Fatal("defaults")
	}
}
