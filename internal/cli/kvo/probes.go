package kvo

import (
	"fmt"
	"io"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/probes"
	"kevaso.com/core/internal/routing"
)

// probeWhat is what a probe checks, for people.
func probeWhat(p *v1.Probe) string {
	switch {
	case p.Exec != nil:
		return "exec " + strings.Join(p.Exec.Command, " ")
	case p.TCP != nil:
		return "tcp " + p.TCP.Port
	case p.HTTP != nil:
		path := p.HTTP.Path
		if path == "" {
			path = "/"
		}
		return "http " + p.HTTP.Port + path
	}
	return "-"
}

// writeProbes is a silo's probes table: what each checks, how it's doing, its last result.
func writeProbes(w io.Writer, s *v1.Silo) {
	list := probes.List(s.Spec.Probes)
	if len(list) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "Probes:")
	_, _ = fmt.Fprintln(w, "  PROBE\tCHECK\tEVERY\tSTATE\tLAST\tREASON")
	for _, n := range list {
		st := v1.FindProbe(s.Status.Probes, n.Name)
		if st == nil {
			st = &v1.ProbeStatus{State: v1.ProbePending}
		}
		state := st.State
		if st.Since != nil {
			state += " for " + since(*st.Since)
		}
		every := probes.Period(n.Probe).String()
		switch n.Name {
		case v1.ProbeStartup:
			every += ", within " + probes.Deadline(n.Probe).String()
		case v1.ProbeLiveness:
			every += ", on failure " + probes.OnFailure(n.Probe)
		}
		last := "-"
		if st.LastTime != nil {
			last = st.LastResult + " " + since(*st.LastTime) + " ago"
		}
		_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", n.Name, probeWhat(n.Probe), every, state, last, dash(st.Reason))
	}
	if r := s.Status.Restarts; r != nil && r.Count > 0 {
		last := ""
		if r.Last != nil {
			last = ", last " + since(*r.Last) + " ago"
		}
		_, _ = fmt.Fprintf(w, "Liveness restarts:\t%d%s\n", r.Count, last)
	}
}

// traffic says what a routing decision means for people: routed, or held since when and why.
func traffic(r v1.Routing) string {
	if r.Routed {
		return "routed"
	}
	held := "held"
	if r.Since != nil {
		held += " since " + since(*r.Since)
	}
	return held + " (" + r.Reason + ")"
}

// routeWhenText is the routeWhen in force and whether it was stated.
func routeWhenText(r v1.Routing) string {
	switch {
	case r.Stated:
		return r.RouteWhen
	case r.RouteWhen == v1.RouteWhenRunning:
		return "running (not stated: the silo has no readiness probe)"
	}
	return "not stated"
}

// writeServiceTraffic is, per port of a silo's own service, whether it's routed now.
func writeServiceTraffic(w io.Writer, s *v1.Silo) {
	r := routing.Silo(s.Spec, s.Status)
	if r == nil || len(s.Spec.Service.Ports) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Route when:\t%s\n", routeWhenText(*r))
	_, _ = fmt.Fprintln(w, "Traffic:")
	_, _ = fmt.Fprintln(w, "  PORT\tTRAFFIC")
	for _, p := range s.Spec.Service.Ports {
		_, _ = fmt.Fprintf(w, "  %s %d\t%s\n", p.Name, p.Port, traffic(*r))
	}
}

// heldText is a held endpoint's state, for people.
func heldText(ep v1.ServiceEndpoint) string {
	return traffic(v1.Routing{Reason: ep.Reason, Since: ep.Since})
}
