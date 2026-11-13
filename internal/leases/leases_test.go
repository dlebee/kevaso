package leases

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func svc(lease *v1.ServiceLease) *v1.SiloService {
	return &v1.SiloService{
		Ports:    []v1.ServicePort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "disc", Port: 30303, Protocol: "UDP"}},
		Expose:   v1.ExposeHostPort,
		HostPort: &v1.HostPortSpec{Ports: []string{"web", "debug"}, AllowFrom: []string{"203.0.113.0/24"}},
		Lease:    lease,
	}
}

func siloWith(lease *v1.ServiceLease) *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"}, Spec: v1.SiloSpec{Service: svc(lease)}}
}

func TestValidate(t *testing.T) {
	l := Limits{Max: 4 * time.Hour, DefaultMax: time.Hour}
	for _, c := range []struct {
		name  string
		sv    *v1.SiloService
		wants []string // substrings; none = valid
	}{
		{"no lease", svc(nil), nil},
		{"good", svc(&v1.ServiceLease{Ports: []string{"debug"}, Default: "30m", Max: "2h", AllowFrom: []string{"203.0.113.7"}}), nil},
		{"all exposed ports", svc(&v1.ServiceLease{}), nil},
		{"private", &v1.SiloService{Ports: []v1.ServicePort{{Name: "web", Port: 80}}, Lease: &v1.ServiceLease{}}, []string{"only with expose: hostPort or loadBalancer"}},
		{"unknown port", svc(&v1.ServiceLease{Ports: []string{"ssh"}}), []string{`"ssh" isn't a port of the service`}},
		{"port not exposed", svc(&v1.ServiceLease{Ports: []string{"disc"}}), []string{`"disc" isn't exposed`}},
		{"bad durations", svc(&v1.ServiceLease{Default: "soon", Max: "0s"}), []string{"service.lease.max 0s: at least 1s", "default \"soon\" isn't a duration"}},
		{"max over the cluster's", svc(&v1.ServiceLease{Max: "5h"}), []string{"max 5h0m0s is more than this cluster allows (4h0m0s)"}},
		{"default over max", svc(&v1.ServiceLease{Default: "3h", Max: "2h"}), []string{"default 3h0m0s is more than its max (2h0m0s)"}},
		{"default over the cluster's default max", svc(&v1.ServiceLease{Default: "90m"}), []string{"more than its max (1h0m0s)"}},
		{"bad source", svc(&v1.ServiceLease{AllowFrom: []string{"office"}}), []string{`allowFrom: "office"`}},
	} {
		errs := Validate(c.sv, l)
		if len(c.wants) == 0 && len(errs) > 0 {
			t.Errorf("%s: %v", c.name, errs)
		}
		for _, w := range c.wants {
			if !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, w) }) {
				t.Errorf("%s: %v, want %q", c.name, errs, w)
			}
		}
	}
}

func TestDuration(t *testing.T) {
	l := Limits{Max: 3 * time.Hour, DefaultMax: time.Hour}
	for _, c := range []struct {
		name    string
		lease   *v1.ServiceLease
		ask     string
		want    time.Duration
		clamped bool
		err     string
	}{
		{"the silo's default", &v1.ServiceLease{Default: "10m", Max: "2h"}, "", 10 * time.Minute, false, ""},
		{"no default: 30m", &v1.ServiceLease{Max: "2h"}, "", 30 * time.Minute, false, ""},
		{"no default, short max", &v1.ServiceLease{Max: "5m"}, "", 5 * time.Minute, false, ""},
		{"as asked", &v1.ServiceLease{Max: "2h"}, "1h", time.Hour, false, ""},
		{"cut to the silo's max", &v1.ServiceLease{Max: "2h"}, "5h", 2 * time.Hour, true, ""},
		{"no max: the cluster's default max", &v1.ServiceLease{}, "5h", time.Hour, true, ""},
		{"a max the cluster lowered since", &v1.ServiceLease{Max: "8h"}, "8h", 3 * time.Hour, true, ""},
		{"not a duration", &v1.ServiceLease{}, "a while", 0, false, "isn't a duration"},
		{"too short", &v1.ServiceLease{}, "10ms", 0, false, "at least 1s"},
	} {
		d, clamped, err := Duration(c.ask, svc(c.lease), l)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil || d != c.want || clamped != c.clamped {
			t.Errorf("%s: %v %v %v, want %v %v", c.name, d, clamped, err, c.want, c.clamped)
		}
	}
}

func TestSources(t *testing.T) {
	for _, c := range []struct {
		service, lease, want []string
	}{
		{nil, nil, nil},
		{[]string{"10.0.0.0/8"}, nil, []string{"10.0.0.0/8"}},
		{nil, []string{"203.0.113.0/24"}, []string{"203.0.113.0/24"}},
		{[]string{"203.0.113.0/24"}, []string{"203.0.113.7"}, []string{"203.0.113.7"}},
		{[]string{"203.0.113.7/32"}, []string{"203.0.113.0/24"}, []string{"203.0.113.7"}}, // never wider
		{[]string{"203.0.113.0/24", "198.51.100.0/24"}, []string{"0.0.0.0/0"}, []string{"203.0.113.0/24", "198.51.100.0/24"}},
		{[]string{"203.0.113.0/24"}, []string{"198.51.100.0/24"}, []string{}}, // no overlap: nobody
	} {
		got := Sources(c.service, c.lease)
		if !slices.Equal(got, c.want) || (c.want != nil && got == nil) || (c.want == nil && got != nil) {
			t.Errorf("Sources(%v, %v) = %#v, want %#v", c.service, c.lease, got, c.want)
		}
	}
}

func TestLeased(t *testing.T) {
	if got := Leased(svc(&v1.ServiceLease{})); !slices.Equal(got, []string{"web", "debug"}) {
		t.Errorf("default: %v", got)
	}
	if got := Leased(svc(&v1.ServiceLease{Ports: []string{"debug"}})); !slices.Equal(got, []string{"debug"}) {
		t.Errorf("listed: %v", got)
	}
	lb := svc(&v1.ServiceLease{})
	lb.Expose, lb.HostPort = v1.ExposeLoadBalancer, nil
	if got := Leased(lb); len(got) != 3 {
		t.Errorf("load balancer: every port: %v", got)
	}
	if Leased(svc(nil)) != nil {
		t.Error("no lease, no leased ports")
	}
}

var (
	limits = Limits{Max: 4 * time.Hour, DefaultMax: time.Hour}
	alim   = approvals.Limits{DefaultWait: 10 * time.Minute, MaxWait: time.Hour}
)

func ask(by, f string) Ask {
	return Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "debug", For: f, By: by}
}

func TestOpenWithoutApproval(t *testing.T) {
	s := siloWith(&v1.ServiceLease{Ports: []string{"debug"}, Max: "2h"})
	out := Decide(ask("system:silo:dev:api", "5h"), s, nil, nil, limits, alim, t0)
	if out.Err != nil || !out.Open || !out.Clamped || out.Lease == nil || out.Event != "lease-opened" {
		t.Fatalf("outcome %+v", out)
	}
	l := out.Lease
	if l.Name != Name("api", "debug") || l.Status.Phase != v1.LeaseOpen || !l.Status.Until.Equal(t0.Add(2*time.Hour)) || l.Status.RequestedBy != "system:silo:dev:api" {
		t.Fatalf("lease %+v", l.Status)
	}
	// Open now, closed at its end exactly.
	if !l.IsOpen("u1", t0.Add(2*time.Hour-time.Second)) || l.IsOpen("u1", t0.Add(2*time.Hour)) {
		t.Error("open window")
	}
	// Not for a new silo of the same name.
	if l.IsOpen("u2", t0) {
		t.Error("open for another silo")
	}
	// A port that isn't leased.
	if out := Decide(Ask{Silo: "api", SiloUID: "u1", Port: "web"}, s, nil, nil, limits, alim, t0); !errors.Is(out.Err, ErrNotLeased) {
		t.Errorf("web: %v", out.Err)
	}
	// Extending is a new ask: a new end, from now.
	out2 := Decide(ask("ada", "30m"), s, l, nil, limits, alim, t0.Add(time.Hour))
	if !out2.Open || !out2.Lease.Status.Until.Equal(t0.Add(90*time.Minute)) || out2.Lease.Status.RequestedBy != "ada" {
		t.Errorf("extension: %+v", out2.Lease.Status)
	}
}

func TestApprovalFlow(t *testing.T) {
	s := siloWith(&v1.ServiceLease{Ports: []string{"debug"}, Max: "2h", Approval: &v1.ApprovalRule{Required: true}})
	a := ask("system:silo:dev:api", "1h")
	a.Wait = "5m"
	out := Decide(a, s, nil, nil, limits, alim, t0)
	if out.Err != nil || out.Open || out.Wait == nil || out.Approval == nil || out.Event != "lease-asked" {
		t.Fatalf("ask: %+v", out)
	}
	appr := out.Approval
	if appr.Spec.Use != v1.ApprovalForExpose || appr.Spec.Port != "debug" || appr.Spec.Secret != "" || appr.Spec.For != "1h0m0s" ||
		!appr.Spec.ExpiresAt.Equal(t0.Add(5*time.Minute)) || !strings.Contains(appr.Spec.Summary, "open port debug (9229/TCP)") {
		t.Fatalf("approval %+v", appr.Spec)
	}
	lease := out.Lease
	if lease.Status.Phase != v1.LeasePending || lease.Status.Pending == nil || lease.Status.Pending.Approval != appr.Name || lease.IsOpen("u1", t0) {
		t.Fatalf("pending lease %+v", lease.Status)
	}
	if st := States(s, []*v1.Lease{lease}, t0); len(st) != 1 || st[0].Phase != v1.LeasePending {
		t.Errorf("states %+v", st)
	}
	// Polling while pending: wait.
	p := a
	p.Poll = appr.Name
	if o := Decide(p, s, lease, appr, limits, alim, t0.Add(time.Minute)); o.Wait == nil || o.Lease != nil || o.Approval != nil {
		t.Fatalf("poll pending: %+v", o)
	}
	// Asking again replaces it (same name, new expiry).
	again := Decide(a, s, lease, appr, limits, alim, t0.Add(2*time.Minute))
	if again.Event != "lease-replaced" || again.Approval.Name != appr.Name || !again.Approval.Spec.ExpiresAt.Equal(t0.Add(7*time.Minute)) {
		t.Fatalf("again: %+v", again)
	}
	appr, lease = again.Approval, again.Lease
	// A person says yes: the port opens for the time asked, from the answer.
	yes, err := approvals.Answer(appr, true, "ada", "", t0.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	opened := Answered(lease, yes, t0.Add(3*time.Minute))
	if opened == nil || !opened.IsOpen("u1", t0.Add(3*time.Minute)) || !opened.Status.Until.Equal(t0.Add(63*time.Minute)) ||
		opened.Status.ApprovedBy != "ada" || opened.Status.RequestedBy != "system:silo:dev:api" || opened.Status.Pending != nil {
		t.Fatalf("approved: %+v", opened)
	}
	// The silo's poll now goes through.
	if o := Decide(p, s, opened, yes, limits, alim, t0.Add(4*time.Minute)); !o.Open || !o.Until.Equal(t0.Add(63*time.Minute)) {
		t.Fatalf("poll approved: %+v", o)
	}
	// After its end the same approval doesn't reopen it.
	if o := Decide(p, s, opened, yes, limits, alim, t0.Add(2*time.Hour)); !errors.Is(o.Err, ErrEnded) {
		t.Fatalf("poll after the end: %+v", o)
	}
	// An approval that isn't the lease's pending ask changes nothing.
	if Answered(opened, yes, t0) != nil {
		t.Error("answered twice")
	}

	// Extending while open: the port stays open while the new ask waits; denied, it stays open
	// until its own end.
	ext := Decide(a, s, opened, yes, limits, alim, t0.Add(30*time.Minute))
	if ext.Lease.Status.Phase != v1.LeaseOpen || !ext.Lease.IsOpen("u1", t0.Add(30*time.Minute)) || ext.Lease.Status.Pending == nil {
		t.Fatalf("extension: %+v", ext.Lease.Status)
	}
	if st := States(s, []*v1.Lease{ext.Lease}, t0.Add(30*time.Minute)); st[0].Phase != v1.LeaseOpen || !st[0].Pending {
		t.Errorf("extension states %+v", st)
	}
	no, _ := approvals.Answer(ext.Approval, false, "ada", "enough", t0.Add(31*time.Minute))
	denied := Answered(ext.Lease, no, t0.Add(31*time.Minute))
	if denied.Status.Phase != v1.LeaseOpen || denied.Status.Pending != nil || denied.Status.Reason != "denied by ada: enough" {
		t.Fatalf("denied extension: %+v", denied.Status)
	}
	// Denied when closed: Denied; the poll says by whom.
	first := Decide(a, s, nil, nil, limits, alim, t0)
	no2, _ := approvals.Answer(first.Approval, false, "ada", "", t0.Add(time.Minute))
	if d := Answered(first.Lease, no2, t0.Add(time.Minute)); d.Status.Phase != v1.LeaseDenied {
		t.Fatalf("denied: %+v", d.Status)
	}
	p.Poll = no2.Name
	if o := Decide(p, s, first.Lease, no2, limits, alim, t0.Add(time.Minute)); o.Err == nil || !strings.Contains(o.Err.Error(), "denied by ada") {
		t.Fatalf("poll denied: %+v", o)
	}
}

func TestApprovalExpires(t *testing.T) {
	s := siloWith(&v1.ServiceLease{Approval: &v1.ApprovalRule{Required: true}})
	a := ask("system:silo:dev:api", "")
	out := Decide(a, s, nil, nil, limits, alim, t0)
	if !out.Approval.Spec.ExpiresAt.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("default wait: %v", out.Approval.Spec.ExpiresAt)
	}
	if out.Approval.Spec.For != "30m0s" {
		t.Fatalf("default for: %v", out.Approval.Spec.For)
	}
	a.Poll = out.Approval.Name
	o := Decide(a, s, out.Lease, out.Approval, limits, alim, t0.Add(10*time.Minute))
	if !errors.Is(o.Err, approvals.ErrExpired) || o.Approval == nil || o.Approval.Status.Phase != v1.ApprovalExpired ||
		o.Lease == nil || o.Lease.Status.Phase != v1.LeaseExpired || o.Lease.Status.Pending != nil {
		t.Fatalf("expired: %+v", o)
	}
	// Too long a wait is refused.
	a.Poll, a.Wait = "", "2h"
	if o := Decide(a, s, nil, nil, limits, alim, t0); o.Err == nil || !strings.Contains(o.Err.Error(), "more than this cluster allows") {
		t.Fatalf("long wait: %v", o.Err)
	}
}

func TestApproverOpensDirectly(t *testing.T) {
	s := siloWith(&v1.ServiceLease{Approval: &v1.ApprovalRule{Required: true}})
	// Someone else's ask is pending; an approver's own ask opens it, and ends that one.
	pending := Decide(ask("ed", "10m"), s, nil, nil, limits, alim, t0)
	a := ask("ada", "20m")
	a.MayApprove = true
	out := Decide(a, s, pending.Lease, pending.Approval, limits, alim, t0.Add(time.Minute))
	if !out.Open || out.Lease.Status.ApprovedBy != "ada" || out.Lease.Status.Pending != nil {
		t.Fatalf("approver's ask: %+v", out.Lease.Status)
	}
	if out.Approval == nil || out.Approval.Status.Phase != v1.ApprovalExpired || !strings.Contains(out.Approval.Status.Reason, "opened by ada") {
		t.Fatalf("overtaken approval: %+v", out.Approval)
	}
}

func TestCloseAndSweep(t *testing.T) {
	s := siloWith(&v1.ServiceLease{Max: "2h"})
	out := Decide(ask("ada", "1h"), s, nil, nil, limits, alim, t0)
	closed, _, err := Close(out.Lease, nil, "u1", "ed", t0.Add(10*time.Minute))
	if err != nil || closed.IsOpen("u1", t0.Add(10*time.Minute)) || closed.Status.Phase != v1.LeaseClosed ||
		!closed.Status.Until.Equal(t0.Add(10*time.Minute)) || closed.Status.Reason != "closed by ed" {
		t.Fatalf("closed: %+v %v", closed, err)
	}
	if _, _, err := Close(closed, nil, "u1", "ed", t0.Add(11*time.Minute)); !errors.Is(err, ErrNotOpen) {
		t.Fatalf("close twice: %v", err)
	}
	// Closing drops a pending ask, so a late yes opens nothing.
	sa := siloWith(&v1.ServiceLease{Approval: &v1.ApprovalRule{Required: true}})
	p := Decide(ask("ed", ""), sa, nil, nil, limits, alim, t0)
	c, ended, err := Close(p.Lease, p.Approval, "u1", "ed", t0.Add(time.Minute))
	if err != nil || c.Status.Pending != nil || ended == nil || ended.Status.Phase != v1.ApprovalExpired {
		t.Fatalf("close pending: %+v %+v %v", c, ended, err)
	}

	// Sweep: time up, and asks that expired unanswered.
	open1 := out.Lease
	if got := Sweep([]*v1.Lease{open1, p.Lease}, t0.Add(5*time.Minute)); len(got) != 0 {
		t.Fatalf("nothing to sweep yet: %+v", got)
	}
	got := Sweep([]*v1.Lease{open1, p.Lease}, t0.Add(time.Hour))
	if len(got) != 2 || got[0].Status.Phase != v1.LeaseClosed || got[0].Status.Reason != "time up" ||
		got[1].Status.Phase != v1.LeaseExpired || got[1].Status.Pending != nil {
		t.Fatalf("sweep: %+v", got)
	}
}

func TestOpenAtAMoment(t *testing.T) {
	s := siloWith(&v1.ServiceLease{})
	web := Decide(Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "web", For: "10m", By: "ada"}, s, nil, nil, limits, alim, t0).Lease
	debug := Decide(ask("ada", "40m"), s, nil, nil, limits, alim, t0).Lease
	other := Decide(Ask{Namespace: "dev", Silo: "api", SiloUID: "old", Port: "debug", For: "1h", By: "ada"}, s, nil, nil, limits, alim, t0).Lease
	all := []*v1.Lease{web, debug, other}
	if got := Closed(s, all, t0); len(got) != 0 {
		t.Errorf("at t0: closed %v", got)
	}
	if got := Closed(s, all, t0.Add(10*time.Minute)); !slices.Equal(got, []string{"web"}) {
		t.Errorf("at 10m: closed %v", got)
	}
	if got := Closed(s, all, t0.Add(time.Hour)); !slices.Equal(got, []string{"web", "debug"}) {
		t.Errorf("at 1h: closed %v", got)
	}
	if got := Closed(s, nil, t0); !slices.Equal(got, []string{"web", "debug"}) {
		t.Errorf("no leases: closed %v", got)
	}
	// When to wake: the next end after now.
	if n := Next(all, t0); !n.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("next at t0: %v", n)
	}
	if n := Next(all, t0.Add(10*time.Minute)); !n.Equal(t0.Add(40 * time.Minute)) {
		t.Errorf("next at 10m: %v", n)
	}
	if n := Next(all, t0.Add(2*time.Hour)); !n.IsZero() {
		t.Errorf("next at 2h: %v", n)
	}
}

func TestName(t *testing.T) {
	if Name("a-b", "c") == Name("a", "b-c") {
		t.Error("names collide")
	}
	long := Name(strings.Repeat("s", 63), strings.Repeat("p", 63))
	if err := meta.ValidateName(long); err != nil {
		t.Error(err)
	}
}
