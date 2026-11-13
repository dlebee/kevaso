package probes

import (
	"fmt"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// Validate checks a silo spec's probes and its service's routeWhen (design §0.6): each probe is
// one of exec, tcp or http; ports are numbers or the service's port names; onFailure is for
// liveness; routeWhen: ready needs a readiness probe, and a silo with both a readiness probe and a
// service must say routeWhen. Pure.
func Validate(spec v1.SiloSpec) []string {
	var errs []string
	for _, n := range List(spec.Probes) {
		p, f := n.Probe, "probes."+n.Name
		kinds := 0
		for _, set := range []bool{p.Exec != nil, p.TCP != nil, p.HTTP != nil} {
			if set {
				kinds++
			}
		}
		if kinds != 1 {
			errs = append(errs, f+": needs exactly one of exec, tcp or http")
		}
		if p.Exec != nil && len(p.Exec.Command) == 0 {
			errs = append(errs, f+".exec: needs a command")
		}
		if p.TCP != nil {
			errs = append(errs, checkPort(f+".tcp.port", p.TCP.Port, spec)...)
		}
		if p.HTTP != nil {
			errs = append(errs, checkPort(f+".http.port", p.HTTP.Port, spec)...)
			if p.HTTP.Path != "" && !strings.HasPrefix(p.HTTP.Path, "/") {
				errs = append(errs, fmt.Sprintf("%s.http.path: %q must start with /", f, p.HTTP.Path))
			}
		}
		for field, d := range map[string]string{"period": p.Period, "timeout": p.Timeout} {
			if d == "" {
				continue
			}
			if v, err := time.ParseDuration(d); err != nil || v <= 0 {
				errs = append(errs, fmt.Sprintf("%s.%s: %q isn't a duration (e.g. 10s)", f, field, d))
			}
		}
		if p.Successes < 0 || p.Failures < 0 {
			errs = append(errs, f+": successes and failures can't be negative")
		}
		if n.Name == v1.ProbeStartup && p.Failures != 0 {
			errs = append(errs, f+".failures: startup fails only by its deadline (timeout)")
		}
		if p.OnFailure != "" {
			switch {
			case n.Name != v1.ProbeLiveness:
				errs = append(errs, f+".onFailure: only liveness has one")
			case p.OnFailure != v1.OnFailureReport && p.OnFailure != v1.OnFailureRestart:
				errs = append(errs, f+".onFailure: report or restart")
			}
		}
	}
	if sv := spec.Service; sv != nil {
		switch sv.RouteWhen {
		case "":
			if spec.HasReadiness() {
				errs = append(errs, "service.routeWhen: the silo has a readiness probe and a service, so say whether traffic waits for it: ready or running")
			}
		case v1.RouteWhenReady:
			if !spec.HasReadiness() {
				errs = append(errs, "service.routeWhen: ready needs a readiness probe (probes.readiness)")
			}
		case v1.RouteWhenRunning:
		default:
			errs = append(errs, "service.routeWhen: ready or running")
		}
	}
	return errs
}

func checkPort(field, port string, spec v1.SiloSpec) []string {
	if port == "" {
		return []string{field + ": needed (a declared port's name, from spec.ports)"}
	}
	if _, ok := ResolvePort(port, spec); !ok {
		return []string{fmt.Sprintf("%s: %q isn't one of the silo's declared ports (spec.ports)", field, port)}
	}
	return nil
}

// ResolvePort is a tcp or http probe's port number: the declared port of that name (ok false: no
// such port, so the probe can't run).
func ResolvePort(port string, spec v1.SiloSpec) (int, bool) {
	d, ok := spec.Declared(port)
	return d.Port, ok
}
