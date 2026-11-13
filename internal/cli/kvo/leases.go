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

// Ports opened on a lease (design §7.2d): kvo open silo NAME --port P [--for D] [--no-wait] and
// kvo close silo NAME --port P. Opening needs the verb open on silos/exposure; when the silo's
// lease needs a yes, it waits for one (kvo approve) unless you hold approve there yourself.

type leaseOpts struct {
	port, forDur string
	noWait       bool
}

// leasePoll is how often kvo open looks at a lease waiting for a yes.
var leasePoll = 2 * time.Second

func leaseCommand(ctx context.Context, c *client.Client, o opts, verb string, stdout, stderr io.Writer) error {
	if len(o.args) != 2 || (o.args[0] != "silo" && o.args[0] != "silos") || o.lease.port == "" {
		return fmt.Errorf("usage: kvo %s silo NAME --port PORT%s", verb, map[bool]string{true: " [--for 1h] [--no-wait]"}[verb == "open"])
	}
	ns, name := defaultNS(o), o.args[1]
	path := "/apis/kevaso/v1/namespaces/" + url.PathEscape(ns) + "/silos/" + url.PathEscape(name) + "/" + verb
	var ans client.LeaseAnswer
	if err := c.Call(ctx, http.MethodPost, path, v1.LeaseOpenRequest{Port: o.lease.port, For: o.lease.forDur}, &ans); err != nil {
		return err
	}
	l := ans.Lease
	what := fmt.Sprintf("silo/%s port %s", name, o.lease.port)
	if verb == "close" {
		_, err := fmt.Fprintln(stdout, what+": closed")
		return err
	}
	if ans.Clamped {
		_, _ = fmt.Fprintf(stderr, "kvo: %s: %s is more than its lease's max: asked for the max instead\n", what, o.lease.forDur)
	}
	if l.IsOpen(l.Spec.SiloUID, time.Now()) && l.Status.Pending == nil {
		_, err := fmt.Fprintf(stdout, "%s: open until %s\n", what, l.Status.Until.Local().Format(time.Kitchen))
		return err
	}
	p := l.Status.Pending
	if p == nil {
		return fmt.Errorf("%s: %s", what, dash(l.Status.Reason))
	}
	_, _ = fmt.Fprintf(stdout, "%s: waiting for a yes: kvo approve %s -n %s (expires %s)\n", what, p.Approval, ns, p.ExpiresAt.Local().Format(time.Kitchen))
	if o.lease.noWait {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("stopped waiting for approval %s: %w", p.Approval, ctx.Err())
		case <-time.After(leasePoll):
		}
		var cur v1.Lease
		if err := c.Get(ctx, "Lease", ns, l.Name, &cur); err != nil {
			return err
		}
		if cur.Status.Pending != nil && cur.Status.Pending.Approval == p.Approval && time.Now().Before(cur.Status.Pending.ExpiresAt) {
			continue
		}
		if cur.Status.ApprovedBy != "" && cur.IsOpen(cur.Spec.SiloUID, time.Now()) && cur.Status.Reason == "" {
			_, err := fmt.Fprintf(stdout, "%s: approved by %s: open until %s\n", what, cur.Status.ApprovedBy, cur.Status.Until.Local().Format(time.Kitchen))
			return err
		}
		if cur.Status.Pending != nil && !time.Now().Before(cur.Status.Pending.ExpiresAt) {
			return fmt.Errorf("%s: approval %s expired: nobody answered in time", what, p.Approval)
		}
		return fmt.Errorf("%s: %s", what, dash(cur.Status.Reason))
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

// describeLeases adds a silo's leased ports to kvo describe silo: each closed, pending or open
// until a time.
func describeLeases(ctx context.Context, c *client.Client, s *v1.Silo, w io.Writer) error {
	sv := s.Spec.Service
	if sv == nil || sv.Lease == nil {
		return nil
	}
	ls := sv.Lease
	terms := []string{"default " + orDash(ls.Default, "30m or its max"), "max " + orDash(ls.Max, "the cluster's")}
	if ls.Approval != nil && ls.Approval.Required {
		terms = append(terms, "a person's yes first")
	}
	if len(ls.AllowFrom) > 0 {
		terms = append(terms, "from "+strings.Join(ls.AllowFrom, ", "))
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
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Leased ports:\t%s\n", strings.Join(terms, ", "))
	if err != nil {
		_, _ = fmt.Fprintf(tw, "  (can't read leases: %v)\n", err)
		return tw.Flush()
	}
	_, _ = fmt.Fprintln(tw, "  PORT\tSTATE")
	now := time.Now()
	for _, st := range leases.States(s, all, now) {
		state := "closed"
		switch st.Phase {
		case v1.LeaseOpen:
			state = "open until " + st.Until.Local().Format(time.Kitchen)
			if st.Pending {
				state += " (an extension waits for a yes)"
			}
		case v1.LeasePending:
			state = "pending: waiting for a yes until " + st.Until.Local().Format(time.Kitchen)
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\n", st.Port, state)
	}
	return tw.Flush()
}

func orDash(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
