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

// svc is a silo spec whose service has web always open on the host, debug leased on the given
// terms (nil: not leased) and disc open on its silo IP only (not outside).
func svc(debug *v1.PortLease) v1.SiloSpec {
	ext := []string{v1.NetworkExternal}
	return v1.SiloSpec{
		Ports: []v1.SiloPort{{Name: "web", Port: 8080}, {Name: "debug", Port: 9229}, {Name: "disc", Port: 30303, Protocol: "UDP"}},
		Service: &v1.SiloService{Ports: []v1.ServicePort{
			{Port: "web", HostPort: ext, Sources: []string{"203.0.113.0/24"}},
			{Port: "debug", HostPort: ext, Sources: []string{"203.0.113.0/24"}, Lease: debug},
			{Port: "disc"},
		}},
	}
}

// withLease gives one more port of spec a lease.
func withLease(spec v1.SiloSpec, port string, pl *v1.PortLease) v1.SiloSpec {
	for i := range spec.Service.Ports {
		if spec.Service.Ports[i].Port == port {
			spec.Service.Ports[i].Lease = pl
		}
	}
	return spec
}

func siloWith(debug *v1.PortLease) *v1.Silo {
	return &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"}, Spec: svc(debug)}
}

func TestValidate(t *testing.T) {
	l := Limits{Max: 4 * time.Hour, DefaultMax: time.Hour}
	for _, c := range []struct {
		name  string
		sv    v1.SiloSpec
		wants []string // substrings; none = valid
	}{
		{"no lease", svc(nil), nil},
		{"good", svc(&v1.PortLease{Default: "30m", Max: "2h"}), nil},
		{"empty lease: closed until leased", svc(&v1.PortLease{}), nil},
		{"two ports, their own terms", withLease(svc(&v1.PortLease{Max: "2h", Approval: &v1.ApprovalRule{Required: true}}), "web", &v1.PortLease{Max: "4h"}), nil},
		{"private", v1.SiloSpec{Ports: []v1.SiloPort{{Name: "web", Port: 80}}, Service: &v1.SiloService{Ports: []v1.ServicePort{{Port: "web", Lease: &v1.PortLease{}}}}},
			[]string{"service.ports[web].lease: only on a port with hostPort or loadBalancer"}},
		{"port not outside", withLease(svc(nil), "disc", &v1.PortLease{}), []string{"service.ports[disc].lease: only on a port with hostPort or loadBalancer"}},
		{"bad durations", svc(&v1.PortLease{Default: "soon", Max: "0s"}), []string{"service.ports[debug].lease.max 0s: at least 1s", "default \"soon\" isn't a duration"}},
		{"max over the cluster's", svc(&v1.PortLease{Max: "5h"}), []string{"max 5h0m0s is more than this cluster allows (4h0m0s)"}},
		{"default over max", svc(&v1.PortLease{Default: "3h", Max: "2h"}), []string{"default 3h0m0s is more than its max (2h0m0s)"}},
		{"default over the cluster's default max", svc(&v1.PortLease{Default: "90m"}), []string{"more than its max (1h0m0s)"}},
		// (lease.allowFrom is gone: a leased port's sources are the port's own, checked by admission.)
		{"each port checked on its own", withLease(svc(&v1.PortLease{Max: "2h"}), "web", &v1.PortLease{Max: "5h"}),
			[]string{"service.ports[web].lease.max 5h0m0s is more than this cluster allows"}},
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
		if c.name == "each port checked on its own" && len(errs) != 1 {
			t.Errorf("%s: only web's max is wrong: %v", c.name, errs)
		}
	}
}

func TestDuration(t *testing.T) {
	l := Limits{Max: 3 * time.Hour, DefaultMax: time.Hour}
	for _, c := range []struct {
		name    string
		lease   *v1.PortLease
		ask     string
		want    time.Duration
		clamped bool
		err     string
	}{
		{"the port's default", &v1.PortLease{Default: "10m", Max: "2h"}, "", 10 * time.Minute, false, ""},
		{"no default: 30m", &v1.PortLease{Max: "2h"}, "", 30 * time.Minute, false, ""},
		{"no default, short max", &v1.PortLease{Max: "5m"}, "", 5 * time.Minute, false, ""},
		{"as asked", &v1.PortLease{Max: "2h"}, "1h", time.Hour, false, ""},
		{"cut to the port's max", &v1.PortLease{Max: "2h"}, "5h", 2 * time.Hour, true, ""},
		{"no max: the cluster's default max", &v1.PortLease{}, "5h", time.Hour, true, ""},
		{"a max the cluster lowered since", &v1.PortLease{Max: "8h"}, "8h", 3 * time.Hour, true, ""},
		{"not a duration", &v1.PortLease{}, "a while", 0, false, "isn't a duration"},
		{"too short", &v1.PortLease{}, "10ms", 0, false, "at least 1s"},
	} {
		d, clamped, err := Duration(c.ask, c.lease, l)
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

// TestSources is gone with leases.Sources: a lease no longer narrows its port's sources.

func TestLeased(t *testing.T) {
	if got := Leased(svc(&v1.PortLease{})); !slices.Equal(got, []string{"debug"}) {
		t.Errorf("debug: %v", got)
	}
	if got := Leased(withLease(svc(&v1.PortLease{}), "web", &v1.PortLease{})); !slices.Equal(got, []string{"web", "debug"}) {
		t.Errorf("web and debug: %v", got)
	}
	// A lease on a port the service doesn't open outside leases nothing (admission refuses it anyway).
	if got := Leased(withLease(svc(nil), "disc", &v1.PortLease{})); got != nil {
		t.Errorf("disc isn't outside: %v", got)
	}
	lb := withLease(svc(&v1.PortLease{}), "disc", &v1.PortLease{})
	lb.Service.Ports[2].LoadBalancer = true
	if got := Leased(lb); !slices.Equal(got, []string{"debug", "disc"}) {
		t.Errorf("on the load balancer, disc is outside: %v", got)
	}
	if got := Exposed(svc(nil)); !slices.Equal(got, []string{"web", "debug"}) {
		t.Errorf("exposed: %v", got)
	}
	if Leased(svc(nil)) != nil || Any(svc(nil)) || !Any(svc(&v1.PortLease{})) {
		t.Error("no lease, no leased ports")
	}
	if Of(svc(&v1.PortLease{Max: "2h"}), "web") != nil || Of(svc(&v1.PortLease{Max: "2h"}), "debug").Max != "2h" {
		t.Error("Of")
	}
}

// Each leased port has its own terms and its own lease: different maxes, one needs a yes and one
// doesn't, its own sources, its own clock; the port without a lease is always open.
func TestTwoLeasedPorts(t *testing.T) {
	sv := svc(&v1.PortLease{Max: "2h", Approval: &v1.ApprovalRule{Required: true}})
	sv.Service.Ports[1].Sources = []string{"203.0.113.7"}
	sv.Ports = append(sv.Ports, v1.SiloPort{Name: "preview", Port: 3000})
	sv.Service.Ports = append(sv.Service.Ports, v1.ServicePort{Port: "preview", HostPort: []string{v1.NetworkExternal}, Lease: &v1.PortLease{Max: "8h", Default: "1h"}})
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "api", UID: "u1"}, Spec: sv}
	lim := Limits{Max: 24 * time.Hour, DefaultMax: time.Hour}
	if errs := Validate(sv, lim); len(errs) > 0 {
		t.Fatal(errs)
	}
	if got := Leased(sv); !slices.Equal(got, []string{"debug", "preview"}) {
		t.Fatalf("leased %v", got)
	}
	if got := Closed(s, nil, t0); !slices.Equal(got, []string{"debug", "preview"}) {
		t.Fatalf("closed until leased: %v", got)
	}
	// The web port is always open: nobody leases it.
	if o := Decide(Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "web", By: "ada"}, s, nil, nil, lim, alim, t0); !errors.Is(o.Err, ErrNotLeased) ||
		!strings.Contains(o.Err.Error(), "leased: debug, preview") {
		t.Errorf("web: %v", o.Err)
	}
	// preview: no approval, its own default and max.
	pa := Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "preview", By: "system:silo:dev:api"}
	pv := Decide(pa, s, nil, nil, lim, alim, t0)
	if !pv.Open || !pv.Until.Equal(t0.Add(time.Hour)) || pv.Lease.Name != Name("api", "preview") {
		t.Fatalf("preview by default: %+v", pv)
	}
	pa.For = "6h"
	if pv = Decide(pa, s, pv.Lease, nil, lim, alim, t0); !pv.Open || pv.Clamped || !pv.Until.Equal(t0.Add(6*time.Hour)) {
		t.Fatalf("preview for 6h (under its own max): %+v", pv)
	}
	// debug: the same 6h is cut to its own max, and waits for a yes.
	da := Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "debug", For: "6h", By: "system:silo:dev:api"}
	dbg := Decide(da, s, nil, nil, lim, alim, t0)
	if dbg.Open || dbg.Wait == nil || !dbg.Clamped || dbg.Approval.Spec.For != "2h0m0s" || dbg.Approval.Spec.Port != "debug" {
		t.Fatalf("debug: %+v", dbg)
	}
	if sum := dbg.Approval.Spec.Summary; !strings.Contains(sum, "open port debug (9229/TCP) to the outside from 203.0.113.7 for 2h0m0s (this port's max 2h0m0s)") {
		t.Errorf("summary: %s", sum)
	}
	all := []*v1.Lease{pv.Lease, dbg.Lease}
	// Opening preview didn't open debug.
	if got := Closed(s, all, t0); !slices.Equal(got, []string{"debug"}) {
		t.Fatalf("closed: %v", got)
	}
	st := States(s, all, t0)
	if len(st) != 2 || st[0].Port != "debug" || st[0].Phase != v1.LeasePending || st[1].Port != "preview" || st[1].Phase != v1.LeaseOpen {
		t.Fatalf("states %+v", st)
	}
	// Approved, debug opens on its own clock (2h from the yes); preview keeps its 6h.
	yes, _ := approvals.Answer(dbg.Approval, true, "ada", "", t0.Add(time.Minute))
	all[1] = Answered(dbg.Lease, yes, t0.Add(time.Minute))
	if got := Closed(s, all, t0.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("both open: %v", got)
	}
	if n := Next(all, t0.Add(time.Minute)); !n.Equal(t0.Add(121 * time.Minute)) {
		t.Errorf("next end: debug's: %v", n)
	}
	if got := Closed(s, all, t0.Add(3*time.Hour)); !slices.Equal(got, []string{"debug"}) {
		t.Errorf("at 3h: only debug's time is up: %v", got)
	}
	// Closing one leaves the other.
	c, _, err := Close(all[1], nil, "u1", "ed", t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := Closed(s, []*v1.Lease{all[0], c}, t0.Add(2*time.Minute)); !slices.Equal(got, []string{"debug"}) {
		t.Errorf("after closing debug: %v", got)
	}
	// (Per-port sources from leases are gone: debug's sources are its own port's, as the summary shows.)
}

var (
	limits = Limits{Max: 4 * time.Hour, DefaultMax: time.Hour}
	alim   = approvals.Limits{DefaultWait: 10 * time.Minute, MaxWait: time.Hour}
)

func ask(by, f string) Ask {
	return Ask{Namespace: "dev", Silo: "api", SiloUID: "u1", Port: "debug", For: f, By: by}
}

func TestOpenWithoutApproval(t *testing.T) {
	s := siloWith(&v1.PortLease{Max: "2h"})
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
	s := siloWith(&v1.PortLease{Max: "2h", Approval: &v1.ApprovalRule{Required: true}})
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
	s := siloWith(&v1.PortLease{Approval: &v1.ApprovalRule{Required: true}})
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
	s := siloWith(&v1.PortLease{Approval: &v1.ApprovalRule{Required: true}})
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
	s := siloWith(&v1.PortLease{Max: "2h"})
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
	sa := siloWith(&v1.PortLease{Approval: &v1.ApprovalRule{Required: true}})
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
	s := siloWith(&v1.PortLease{})
	s.Spec = withLease(s.Spec, "web", &v1.PortLease{})
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
