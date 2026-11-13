package kvo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/leases"
)

// Ports opened on a lease (design §7.2d): kvo open silo NAME --port P [--port Q …] [--for D]
// [--no-wait] and kvo close silo NAME --port P [--port Q …]. Opening needs the verb open on
// silos/exposure. Each port named is its own ask, on its own terms: its own lease, its own max and,
// when its lease needs a yes, its own approval (kvo approve), unless you hold approve there
// yourself. One port refused doesn't stop the others: kvo says which ones were refused and why,
// opens (or waits for) the rest, and exits non-zero.

type leaseOpts struct {
	ports  []string
	forDur string
	noWait bool
}

// leasePoll is how often kvo open looks at a lease waiting for a yes.
var leasePoll = 2 * time.Second

// leaseWait is a port whose ask waits for a yes.
type leaseWait struct {
	port, what, lease, approval string
}

func leaseCommand(ctx context.Context, c *client.Client, o opts, verb string, stdout, stderr io.Writer) error {
	if len(o.args) != 2 || (o.args[0] != "silo" && o.args[0] != "silos") || len(o.lease.ports) == 0 {
		return fmt.Errorf("usage: kvo %s silo NAME --port PORT [--port PORT …]%s", verb, map[bool]string{true: " [--for 1h] [--no-wait]"}[verb == "open"])
	}
	ns, name := defaultNS(o), o.args[1]
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/silos/" + url.PathEscape(name) + "/" + verb
	var refused []string
	var waits []leaseWait
	seen := map[string]bool{}
	for _, port := range o.lease.ports {
		if seen[port] {
			continue
		}
		seen[port] = true
		what := fmt.Sprintf("silo/%s port %s", name, port)
		var ans client.LeaseAnswer
		if err := c.Call(ctx, http.MethodPost, path, v1.LeaseOpenRequest{Port: port, For: o.lease.forDur}, &ans); err != nil {
			if len(o.lease.ports) == 1 {
				return err
			}
			_, _ = fmt.Fprintf(stderr, "kvo: %s: refused: %v\n", what, err)
			refused = append(refused, port)
			continue
		}
		w, err := leaseAnswered(ns, port, what, verb, o.lease.forDur, &ans, stdout, stderr)
		switch {
		case err != nil && len(o.lease.ports) == 1:
			return err
		case err != nil:
			_, _ = fmt.Fprintf(stderr, "kvo: %v\n", err)
			refused = append(refused, port)
		case w != nil:
			waits = append(waits, *w)
		}
	}
	if !o.lease.noWait {
		for _, w := range waits {
			if err := leaseAwait(ctx, c, ns, w, stdout); err != nil {
				if len(o.lease.ports) == 1 {
					return err
				}
				_, _ = fmt.Fprintf(stderr, "kvo: %v\n", err)
				refused = append(refused, w.port)
			}
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("silo/%s: %d of %d ports not %s: %s", name, len(refused), len(seen), map[string]string{"open": "opened", "close": "closed"}[verb], strings.Join(refused, ", "))
	}
	return nil
}

// leaseAnswered prints one port's answer; a non-nil wait is an ask waiting for a yes.
func leaseAnswered(ns, port, what, verb, forDur string, ans *client.LeaseAnswer, stdout, stderr io.Writer) (*leaseWait, error) {
	l := ans.Lease
	if verb == "close" {
		_, err := fmt.Fprintln(stdout, what+": closed")
		return nil, err
	}
	if ans.Clamped {
		_, _ = fmt.Fprintf(stderr, "kvo: %s: %s is more than this port's lease max: asked for the max instead\n", what, forDur)
	}
	if l.IsOpen(l.Spec.SiloUID, time.Now()) && l.Status.Pending == nil {
		_, err := fmt.Fprintf(stdout, "%s: open until %s\n", what, l.Status.Until.Local().Format(time.Kitchen))
		return nil, err
	}
	p := l.Status.Pending
	if p == nil {
		return nil, fmt.Errorf("%s: %s", what, dash(l.Status.Reason))
	}
	_, _ = fmt.Fprintf(stdout, "%s: waiting for a yes: kvo approve %s -n %s (expires %s)\n", what, p.Approval, ns, p.ExpiresAt.Local().Format(time.Kitchen))
	return &leaseWait{port: port, what: what, lease: l.Name, approval: p.Approval}, nil
}

// leaseAwait waits for one port's ask to be answered.
func leaseAwait(ctx context.Context, c *client.Client, ns string, w leaseWait, stdout io.Writer) error {
	for {
		var cur v1.Lease
		if err := c.Get(ctx, "Lease", ns, w.lease, &cur); err != nil {
			return err
		}
		switch {
		case cur.Status.Pending != nil && cur.Status.Pending.Approval == w.approval && time.Now().Before(cur.Status.Pending.ExpiresAt):
			select {
			case <-ctx.Done():
				return fmt.Errorf("stopped waiting for approval %s: %w", w.approval, ctx.Err())
			case <-time.After(leasePoll):
			}
			continue
		case cur.Status.ApprovedBy != "" && cur.IsOpen(cur.Spec.SiloUID, time.Now()) && cur.Status.Reason == "":
			_, err := fmt.Fprintf(stdout, "%s: approved by %s: open until %s\n", w.what, cur.Status.ApprovedBy, cur.Status.Until.Local().Format(time.Kitchen))
			return err
		case cur.Status.Pending != nil && !time.Now().Before(cur.Status.Pending.ExpiresAt):
			return fmt.Errorf("%s: approval %s expired: nobody answered in time", w.what, w.approval)
		}
		return fmt.Errorf("%s: %s", w.what, dash(cur.Status.Reason))
	}
}

var leaseHead = []string{"SILO", "PORT", "PHASE", "WHEN", "BY"}

// leaseColumns are kvo get leases' columns, at now (a lease's time can be up before the control
// plane writes so).
func leaseColumns(l *v1.Lease, now time.Time) []string {
	phase, when := l.Status.Phase, ""
	open := l.Status.Phase == v1.LeaseOpen && l.Status.Until != nil && now.Before(*l.Status.Until)
	pending := l.Status.Pending != nil && now.Before(l.Status.Pending.ExpiresAt)
	switch {
	case open:
		when = "until " + l.Status.Until.Local().Format(time.Kitchen)
		if pending {
			when += ", extension waiting on " + l.Status.Pending.Approval
		}
	case pending:
		phase, when = v1.LeasePending, "waiting on "+l.Status.Pending.Approval+", expires in "+l.Status.Pending.ExpiresAt.Sub(now).Round(time.Second).String()
	case l.Status.Pending != nil:
		phase, when = v1.LeaseExpired, "nobody answered"
	case l.Status.Phase == v1.LeaseOpen:
		phase, when = v1.LeaseClosed, "time up"
	default:
		when = dash(l.Status.Reason)
	}
	by := l.Status.RequestedBy
	if pending {
		by = l.Status.Pending.RequestedBy
	}
	if l.Status.ApprovedBy != "" && l.Status.ApprovedBy != by && !pending {
		by += " (yes: " + l.Status.ApprovedBy + ")"
	}
	return []string{l.Spec.Silo, l.Spec.Port, phase, when, dash(by)}
}

// describeLeases adds a silo's outside ports to kvo describe silo: each always open, or leased with
// its own terms and whether it's closed, pending or open until a time.
func describeLeases(ctx context.Context, c *client.Client, s *v1.Silo, w io.Writer) error {
	sv := s.Spec.Service
	if !leases.Any(sv) {
		return nil
	}
	var all []*v1.Lease
	list, err := c.List(ctx, "Lease", s.Namespace)
	if err != nil && !errors.As(err, new(*client.Error)) {
		return err
	}
	if list != nil {
		for _, raw := range list.Items {
			obj, _, err := v1.Decode(raw)
			if err == nil {
				all = append(all, obj.(*v1.Lease))
			}
		}
	}
	return writePorts(w, s, all, err, time.Now())
}

// writePorts writes each outside port of s at now (readErr: the leases couldn't be read).
func writePorts(w io.Writer, s *v1.Silo, all []*v1.Lease, readErr error, now time.Time) error {
	sv := s.Spec.Service
	err := readErr
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "Outside ports:")
	_, _ = fmt.Fprintln(tw, "  PORT\tLEASE\tSTATE")
	states := map[string]leases.State{}
	if err == nil {
		for _, st := range leases.States(s, all, now) {
			states[st.Port] = st
		}
	}
	for _, p := range leases.Exposed(sv) {
		pl := leases.Of(sv, p)
		if pl == nil {
			_, _ = fmt.Fprintf(tw, "  %s\t-\talways open\n", p)
			continue
		}
		state := "closed"
		if err != nil {
			state = "?"
		}
		if st, ok := states[p]; ok {
			switch st.Phase {
			case v1.LeaseOpen:
				state = "open until " + st.Until.Local().Format(time.Kitchen)
				if st.Pending {
					state += " (an extension waits for a yes)"
				}
			case v1.LeasePending:
				state = "pending: waiting for a yes until " + st.Until.Local().Format(time.Kitchen)
			}
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\n", p, leaseTerms(pl), state)
	}
	if err != nil {
		_, _ = fmt.Fprintf(tw, "  (can't read leases: %v)\n", err)
	}
	return tw.Flush()
}

// leaseTerms are one port's lease terms, for people.
func leaseTerms(pl *v1.PortLease) string {
	terms := []string{"default " + orDash(pl.Default, "30m or its max"), "max " + orDash(pl.Max, "the cluster's")}
	if pl.Approval != nil && pl.Approval.Required {
		terms = append(terms, "a person's yes first")
	}
	if len(pl.AllowFrom) > 0 {
		terms = append(terms, "from "+strings.Join(pl.AllowFrom, ", "))
	}
	return strings.Join(terms, ", ")
}

func orDash(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
