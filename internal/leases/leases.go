// Package leases decides ports opened on a lease (design §7.2d). It's pure, like approvals: the
// control plane hands it the silo, the port's current Lease (and Approval, when a yes is needed)
// and the time, and gets back what to store and what to answer. The worker and the load-balancer
// controller ask it which ports are open at a moment, and when that next changes.
//
// Each port says for itself whether it's leased and on what terms (its lease: default, max,
// approval, allowFrom); each leased port has its own Lease, so opening one doesn't open another and
// they end on their own clocks.
//
// The flow: someone asks to open a leased port for a while (the silo over its broker, or a person
// with the verb open on silos/exposure). The time is the one asked, never more than that port's
// lease.max, itself never more than the control plane's limit. Without approval.required the port
// opens at once. With it, the ask becomes a pending Approval (use expose) that always expires;
// asking again replaces it; a person with approve on silos/exposure answers it (a person who holds
// that verb and asks opens it at once). The port closes at the lease's end, or earlier with close.
// Extending is a new ask: an open port stays open while an extension waits for its yes.
package leases

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/approvals"
)

// Limits are the control plane's (kevasod control-plane --lease-max, --lease-default-max).
type Limits struct {
	Max        time.Duration // the longest lease any port may get, and the most a port's max may say (24h)
	DefaultMax time.Duration // a port's max when it sets none (1h)
}

// WithDefaults fills what's unset.
func (l Limits) WithDefaults() Limits {
	if l.Max <= 0 {
		l.Max = 24 * time.Hour
	}
	if l.DefaultMax <= 0 {
		l.DefaultMax = time.Hour
	}
	if l.DefaultMax > l.Max {
		l.DefaultMax = l.Max
	}
	return l
}

// DefaultFor is a lease's length when neither the ask nor the port's lease.default says (never
// more than the port's max).
const DefaultFor = 30 * time.Minute

// Name is the Lease's name for a silo's port: the same two always give the same name.
func Name(silo, port string) string {
	h := sha256.Sum256([]byte(silo + "\x00" + port))
	if len(silo) > 30 {
		silo = silo[:30]
	}
	if len(port) > 15 {
		port = port[:15]
	}
	return silo + "-" + port + "-" + hex.EncodeToString(h[:3])
}

// Exposed are the names of the ports a service opens to the outside (hostPort: its listed ports,
// or all; loadBalancer: all). Private services expose none.
func Exposed(sv *v1.SiloService) []string {
	if sv == nil || (sv.Expose != v1.ExposeHostPort && sv.Expose != v1.ExposeLoadBalancer) {
		return nil
	}
	var out []string
	for _, p := range sv.Ports {
		if sv.Expose == v1.ExposeHostPort && sv.HostPort != nil && len(sv.HostPort.Ports) > 0 && !slices.Contains(sv.HostPort.Ports, p.Name) {
			continue
		}
		out = append(out, p.Name)
	}
	return out
}

// Of is the lease terms of the service's port named port: nil unless that port is exposed and says
// lease (a port without lease is always open).
func Of(sv *v1.SiloService, port string) *v1.PortLease {
	if !slices.Contains(Exposed(sv), port) {
		return nil
	}
	for _, p := range sv.Ports {
		if p.Name == port {
			return p.Lease
		}
	}
	return nil
}

// Leased are the names of the exposed ports that open only on a lease, in the service's order.
func Leased(sv *v1.SiloService) []string {
	var out []string
	for _, p := range Exposed(sv) {
		if Of(sv, p) != nil {
			out = append(out, p)
		}
	}
	return out
}

// Any says whether any port of the service is leased.
func Any(sv *v1.SiloService) bool { return len(Leased(sv)) > 0 }

func parse(field, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s %q isn't a duration (e.g. 30m)", field, s)
	}
	if d < time.Second {
		return 0, fmt.Errorf("%s %s: at least 1s", field, s)
	}
	return d, nil
}

// MaxOf is the longest lease a port may get: its lease.max, or the cluster's default limit, never
// more than the cluster's limit.
func MaxOf(pl *v1.PortLease, l Limits) time.Duration {
	l = l.WithDefaults()
	m := l.DefaultMax
	if pl != nil && pl.Max != "" {
		if d, err := parse("max", pl.Max); err == nil {
			m = d
		}
	}
	return min(m, l.Max)
}

// DefaultOf is a port's lease length when the ask names none.
func DefaultOf(pl *v1.PortLease, l Limits) time.Duration {
	m := MaxOf(pl, l)
	if pl != nil && pl.Default != "" {
		if d, err := parse("default", pl.Default); err == nil {
			return min(d, m)
		}
	}
	return min(DefaultFor, m)
}

// Duration is how long an ask gets: the time asked ("" → the port's default), cut to the port's
// max. clamped says it was cut.
func Duration(ask string, pl *v1.PortLease, l Limits) (d time.Duration, clamped bool, err error) {
	if ask == "" {
		return DefaultOf(pl, l), false, nil
	}
	d, err = parse("for", ask)
	if err != nil {
		return 0, false, err
	}
	if m := MaxOf(pl, l); d > m {
		return m, true, nil
	}
	return d, false, nil
}

// Validate is admission for the leases on a silo's service ports, port by port: only on a service
// with an outside exposure, only on a port it exposes, valid durations, default ≤ max ≤ the
// cluster's limit, sources that are CIDRs.
func Validate(sv *v1.SiloService, l Limits) []string {
	if sv == nil {
		return nil
	}
	l = l.WithDefaults()
	outside := sv.Expose == v1.ExposeHostPort || sv.Expose == v1.ExposeLoadBalancer
	exp := Exposed(sv)
	var errs []string
	for _, p := range sv.Ports {
		ls := p.Lease
		if ls == nil {
			continue
		}
		field := fmt.Sprintf("service.ports[%s].lease", p.Name)
		if !outside {
			errs = append(errs, field+": only with expose: hostPort or loadBalancer (private access is never leased: it's allowFrom)")
			continue
		}
		if !slices.Contains(exp, p.Name) {
			errs = append(errs, fmt.Sprintf("%s: %q isn't exposed (service.hostPort.ports)", field, p.Name))
			continue
		}
		max := l.DefaultMax
		if ls.Max != "" {
			switch d, err := parse(field+".max", ls.Max); {
			case err != nil:
				errs = append(errs, err.Error())
			case d > l.Max:
				errs = append(errs, fmt.Sprintf("%s.max %s is more than this cluster allows (%s)", field, d, l.Max))
			default:
				max = d
			}
		}
		if ls.Default != "" {
			d, err := parse(field+".default", ls.Default)
			if err != nil {
				errs = append(errs, err.Error())
			} else if d > max {
				errs = append(errs, fmt.Sprintf("%s.default %s is more than its max (%s)", field, d, max))
			}
		}
		for _, c := range ls.AllowFrom {
			if _, err := prefix(c); err != nil {
				errs = append(errs, fmt.Sprintf("%s.allowFrom: %q isn't an address or CIDR", field, c))
			}
		}
	}
	return errs
}

// ServiceSources are the outside sources of the service itself (hostPort.allowFrom or
// loadBalancer.allowFrom; nil: anywhere).
func ServiceSources(sv *v1.SiloService) []string {
	switch {
	case sv == nil:
		return nil
	case sv.Expose == v1.ExposeHostPort && sv.HostPort != nil:
		return sv.HostPort.AllowFrom
	case sv.Expose == v1.ExposeLoadBalancer && sv.LoadBalancer != nil:
		return sv.LoadBalancer.AllowFrom
	}
	return nil
}

// PortSources are the sources of each leased port whose lease narrows them (lease.allowFrom), by
// port name: the service's sources narrowed by that port's own. Ports missing from it take the
// service's sources.
func PortSources(sv *v1.SiloService) map[string][]string {
	var out map[string][]string
	for _, p := range Leased(sv) {
		if pl := Of(sv, p); len(pl.AllowFrom) > 0 {
			if out == nil {
				out = map[string][]string{}
			}
			out[p] = Sources(ServiceSources(sv), pl.AllowFrom)
		}
	}
	return out
}

func prefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Sources are where an open leased port may be reached from: the service's own sources (nil:
// anywhere) narrowed by lease.allowFrom. A lease never opens wider than the service; when the two
// don't overlap at all, nothing may reach it (an empty, non-nil list).
func Sources(service, lease []string) []string {
	if len(lease) == 0 {
		return service
	}
	if len(service) == 0 {
		return lease
	}
	out := []string{}
	for _, a := range service {
		pa, err := prefix(a)
		if err != nil {
			continue
		}
		for _, b := range lease {
			pb, err := prefix(b)
			if err != nil || !pa.Overlaps(pb) {
				continue
			}
			narrow := pb
			if pa.Bits() > pb.Bits() {
				narrow = pa
			}
			if s := text(narrow); !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// text writes a prefix the way people wrote it: a single address without /32.
func text(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// ── Asking ───────────────────────────────────────────────────────────────────

// Ask is one ask to open a leased port.
type Ask struct {
	Namespace, Silo, SiloUID, Port string
	For                            string // the time asked ("" → the default)
	// By is who asks: system:silo:NS:NAME for the silo, a person's or service account's name.
	By string
	// MayApprove: the asker is a person who holds approve on this silo's exposure, so their own
	// ask needs nobody else's yes.
	MayApprove bool
	// Wait is how long a pending ask waits for an answer ("" → approvals' default).
	Wait string
	// Poll is the approval a waiting silo polls ("" for a new ask).
	Poll string
}

// Outcome is what the control plane stores and answers.
type Outcome struct {
	Lease    *v1.Lease    // to store (nil: unchanged)
	Approval *v1.Approval // to store (a new or replacing request, or one marked expired)
	Open     bool         // the port is open (until Lease.Status.Until, or Until)
	Until    time.Time
	Clamped  bool         // the time asked was more than the max: it got the max
	Wait     *v1.Approval // keep waiting on this pending request
	Err      error
	Event    string // for the audit log: lease-opened, lease-asked, lease-replaced, lease-expired
}

// Errors an asker sees.
var (
	ErrNotLeased = errors.New("not a leased port")
	ErrNotOpen   = errors.New("not open")
	ErrEnded     = errors.New("approved, but the lease has ended")
)

// Check says whether port is a leased port of the silo.
func Check(silo *v1.Silo, port string) error {
	sv := silo.Spec.Service
	if Of(sv, port) != nil {
		return nil
	}
	leased := Leased(sv)
	if len(leased) == 0 {
		return fmt.Errorf("silo %s port %q: %w: none of its ports is leased", silo.Name, port, ErrNotLeased)
	}
	return fmt.Errorf("silo %s port %q: %w (leased: %s)", silo.Name, port, ErrNotLeased, strings.Join(leased, ", "))
}

// newLease is the lease for a silo's port, keeping what an existing one of the same silo says.
func newLease(a Ask, existing *v1.Lease) *v1.Lease {
	if existing != nil && existing.Spec.SiloUID == a.SiloUID {
		c := *existing
		return &c
	}
	return &v1.Lease{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Lease"},
		ObjectMeta: meta.ObjectMeta{Namespace: a.Namespace, Name: Name(a.Silo, a.Port)},
		Spec:       v1.LeaseSpec{Silo: a.Silo, SiloUID: a.SiloUID, Port: a.Port},
		Status:     v1.LeaseStatus{Phase: v1.LeaseClosed},
	}
}

func open(l *v1.Lease, by, approvedBy string, from, until time.Time) {
	f, u := from, until
	l.Status.Phase, l.Status.OpenedAt, l.Status.Until = v1.LeaseOpen, &f, &u
	l.Status.RequestedBy, l.Status.ApprovedBy, l.Status.Pending, l.Status.Reason = by, approvedBy, nil, ""
}

// settle sets the phase from what's left after an ask is gone: open stays open, otherwise phase.
func settle(l *v1.Lease, siloUID string, now time.Time, phase, reason string) {
	l.Status.Pending = nil
	l.Status.Reason = reason
	if !l.IsOpen(siloUID, now) {
		l.Status.Phase = phase
	}
}

// Decide answers one ask: a new one, or a silo polling the approval it waits on.
func Decide(a Ask, silo *v1.Silo, existing *v1.Lease, appr *v1.Approval, l Limits, al approvals.Limits, now time.Time) Outcome {
	if err := Check(silo, a.Port); err != nil {
		return Outcome{Err: err}
	}
	sv := silo.Spec.Service
	pl := Of(sv, a.Port)
	d, clamped, err := Duration(a.For, pl, l)
	if err != nil {
		return Outcome{Err: err}
	}
	if a.Poll != "" {
		if out, ok := poll(a, existing, appr, now); ok {
			out.Clamped = clamped // the poll repeats the ask
			return out
		}
		// The approval it waited on is gone: ask again.
	}
	lease := newLease(a, existing)
	pendingNow := appr != nil && appr.Spec.SiloUID == a.SiloUID && approvals.StateOf(appr, a.SiloUID, now) == approvals.Pending
	required := pl.Approval != nil && pl.Approval.Required
	if !required || a.MayApprove {
		approvedBy := ""
		if required {
			approvedBy = a.By // they hold approve themselves
		}
		open(lease, a.By, approvedBy, now, now.Add(d))
		out := Outcome{Lease: lease, Open: true, Until: now.Add(d), Clamped: clamped, Event: "lease-opened"}
		if pendingNow { // an ask still waiting is overtaken: it ends, it's not answered later
			c := *appr
			c.Status = v1.ApprovalStatus{Phase: v1.ApprovalExpired, Reason: "replaced: opened by " + a.By}
			out.Approval = &c
		}
		return out
	}
	al = al.WithDefaults()
	wait := al.DefaultWait
	if a.Wait != "" {
		w, err := parse("wait", a.Wait)
		if err != nil {
			return Outcome{Err: err}
		}
		if w > al.MaxWait {
			return Outcome{Err: fmt.Errorf("wait %s is more than this cluster allows (%s)", w, al.MaxWait)}
		}
		wait = w
	}
	proto, port := "TCP", 0
	for _, p := range sv.Ports {
		if p.Name == a.Port {
			port = p.Port
			if p.Protocol != "" {
				proto = p.Protocol
			}
		}
	}
	from := "from anywhere"
	if src := Sources(ServiceSources(sv), pl.AllowFrom); src != nil {
		from = "from " + strings.Join(src, ", ")
		if len(src) == 0 {
			from = "from nowhere (its allowFrom and the service's don't overlap)"
		}
	}
	req := &v1.Approval{
		TypeMeta:   meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Approval"},
		ObjectMeta: meta.ObjectMeta{Namespace: a.Namespace, Name: approvals.Name(a.Silo, a.SiloUID, v1.ApprovalForExpose, a.Port)},
		Spec: v1.ApprovalSpec{Silo: a.Silo, SiloUID: a.SiloUID, Port: a.Port, Use: v1.ApprovalForExpose,
			Summary: fmt.Sprintf("open port %s (%d/%s) to the outside %s for %s (this port's max %s), asked by %s",
				a.Port, port, proto, from, d, MaxOf(pl, l), a.By),
			For:         d.String(),
			RequestedAt: now, ExpiresAt: now.Add(wait)},
		Status: v1.ApprovalStatus{Phase: v1.ApprovalPending},
	}
	lease.Status.Pending = &v1.LeaseAsk{For: d.String(), RequestedBy: a.By, RequestedAt: now, Approval: req.Name, ExpiresAt: req.Spec.ExpiresAt}
	lease.Status.Reason = ""
	if !lease.IsOpen(a.SiloUID, now) {
		lease.Status.Phase = v1.LeasePending
	}
	ev := "lease-asked"
	if pendingNow {
		ev = "lease-replaced"
	}
	return Outcome{Lease: lease, Approval: req, Wait: req, Clamped: clamped, Event: ev}
}

// poll answers a silo waiting on approval a.Poll. ok false: that approval isn't there (ask again).
func poll(a Ask, existing *v1.Lease, appr *v1.Approval, now time.Time) (Outcome, bool) {
	if appr == nil || appr.Name != a.Poll || appr.Spec.SiloUID != a.SiloUID || appr.Spec.Use != v1.ApprovalForExpose {
		return Outcome{}, false
	}
	switch appr.Status.Phase {
	case v1.ApprovalApproved:
		if existing.IsOpen(a.SiloUID, now) {
			return Outcome{Open: true, Until: *existing.Status.Until}, true
		}
		return Outcome{Err: ErrEnded}, true
	case v1.ApprovalDenied:
		err := fmt.Errorf("%w by %s", approvals.ErrDenied, appr.Status.AnsweredBy)
		if appr.Status.Reason != "" {
			err = fmt.Errorf("%w: %s", err, appr.Status.Reason)
		}
		return Outcome{Err: err}, true
	case v1.ApprovalExpired:
		err := approvals.ErrExpired
		if appr.Status.Reason != "" {
			err = fmt.Errorf("%w (%s)", err, appr.Status.Reason)
		}
		return Outcome{Err: err}, true
	}
	if now.Before(appr.Spec.ExpiresAt) {
		return Outcome{Wait: appr}, true
	}
	// Ran out unanswered: say so, and store it.
	c := *appr
	c.Status = v1.ApprovalStatus{Phase: v1.ApprovalExpired}
	out := Outcome{Err: approvals.ErrExpired, Approval: &c, Event: "lease-expired"}
	if l := Answered(existing, &c, now); l != nil {
		out.Lease = l
	}
	return out, true
}

// Answered is the lease once its pending ask's approval was answered (or expired): approved, the
// port opens until the approval's access end; denied or expired, the ask is gone (an open port
// stays open until its own end). nil: the approval isn't this lease's pending ask (nothing to do).
func Answered(l *v1.Lease, a *v1.Approval, now time.Time) *v1.Lease {
	if l == nil || l.Status.Pending == nil || l.Status.Pending.Approval != a.Name || l.Spec.SiloUID != a.Spec.SiloUID {
		return nil
	}
	c := *l
	by := l.Status.Pending.RequestedBy
	switch a.Status.Phase {
	case v1.ApprovalApproved:
		until := now
		if a.Status.AccessUntil != nil {
			until = *a.Status.AccessUntil
		}
		open(&c, by, a.Status.AnsweredBy, now, until)
	case v1.ApprovalDenied:
		reason := "denied by " + a.Status.AnsweredBy
		if a.Status.Reason != "" {
			reason += ": " + a.Status.Reason
		}
		settle(&c, l.Spec.SiloUID, now, v1.LeaseDenied, reason)
	default:
		settle(&c, l.Spec.SiloUID, now, v1.LeaseExpired, "nobody answered "+a.Name+" in time")
	}
	return &c
}

// Close ends a lease early (and drops an ask still waiting). The returned approval, if any, is the
// pending one marked expired, so nobody answers it later.
func Close(l *v1.Lease, appr *v1.Approval, siloUID, by string, now time.Time) (*v1.Lease, *v1.Approval, error) {
	if l == nil || l.Spec.SiloUID != siloUID || (!l.IsOpen(siloUID, now) && l.Status.Pending == nil) {
		return nil, nil, ErrNotOpen
	}
	c := *l
	if c.IsOpen(siloUID, now) {
		t := now
		c.Status.Until = &t
	}
	c.Status.Phase, c.Status.Pending, c.Status.Reason = v1.LeaseClosed, nil, "closed by "+by
	var ended *v1.Approval
	if appr != nil && l.Status.Pending != nil && appr.Name == l.Status.Pending.Approval && approvals.StateOf(appr, siloUID, now) == approvals.Pending {
		e := *appr
		e.Status = v1.ApprovalStatus{Phase: v1.ApprovalExpired, Reason: "closed by " + by}
		ended = &e
	}
	return &c, ended, nil
}

// Sweep returns the leases whose time is up or whose ask expired unanswered, as they should now be
// stored (the control plane runs it every few seconds; the hosts don't wait for it, they close a
// port at its time by themselves).
func Sweep(all []*v1.Lease, now time.Time) []*v1.Lease {
	var out []*v1.Lease
	for _, l := range all {
		c := *l
		changed := false
		if l.Status.Phase == v1.LeaseOpen && l.Status.Until != nil && !now.Before(*l.Status.Until) {
			c.Status.Phase, c.Status.Reason, changed = v1.LeaseClosed, "time up", true
		}
		if p := l.Status.Pending; p != nil && !now.Before(p.ExpiresAt) {
			c.Status.Pending, c.Status.Reason, changed = nil, "nobody answered "+p.Approval+" in time", true
			if c.Status.Phase == v1.LeasePending {
				c.Status.Phase = v1.LeaseExpired
			}
		}
		if changed {
			out = append(out, &c)
		}
	}
	return out
}

// ── What's open ──────────────────────────────────────────────────────────────

// State is one leased port's state for a silo at a moment, for people (kvo describe silo).
type State struct {
	Port    string
	Phase   string    // Closed | Pending | Open
	Until   time.Time // Open: when it closes; Pending: when the ask expires
	Pending bool      // an ask waits for a yes (also while open: an extension)
}

// For returns the lease of each leased port of s (by port name), ignoring leases of an earlier
// silo with the same name.
func For(s *v1.Silo, all []*v1.Lease) map[string]*v1.Lease {
	out := map[string]*v1.Lease{}
	for _, l := range all {
		if l.Namespace == s.Namespace && l.Spec.Silo == s.Name && l.Spec.SiloUID == s.UID {
			out[l.Spec.Port] = l
		}
	}
	return out
}

// States is each leased port of s at now, in the order of its service's ports.
func States(s *v1.Silo, all []*v1.Lease, now time.Time) []State {
	mine := For(s, all)
	var out []State
	for _, p := range Leased(s.Spec.Service) {
		st := State{Port: p, Phase: v1.LeaseClosed}
		l := mine[p]
		switch {
		case l.IsOpen(s.UID, now):
			st.Phase, st.Until = v1.LeaseOpen, *l.Status.Until
			st.Pending = l.Status.Pending != nil && now.Before(l.Status.Pending.ExpiresAt)
		case l != nil && l.Status.Pending != nil && now.Before(l.Status.Pending.ExpiresAt):
			st.Phase, st.Until, st.Pending = v1.LeasePending, l.Status.Pending.ExpiresAt, true
		}
		out = append(out, st)
	}
	return out
}

// Closed are the leased ports of s that are closed at now (no outside rule, no backend).
func Closed(s *v1.Silo, all []*v1.Lease, now time.Time) []string {
	var out []string
	for _, st := range States(s, all, now) {
		if st.Phase != v1.LeaseOpen {
			out = append(out, st.Port)
		}
	}
	return out
}

// Next is the first moment after now when an open lease among all ends (zero: none), so whoever
// enforces leases wakes then even if nothing else changes.
func Next(all []*v1.Lease, now time.Time) time.Time {
	var next time.Time
	for _, l := range all {
		if l.Status.Phase != v1.LeaseOpen || l.Status.Until == nil || !now.Before(*l.Status.Until) {
			continue
		}
		if next.IsZero() || l.Status.Until.Before(next) {
			next = *l.Status.Until
		}
	}
	return next
}
