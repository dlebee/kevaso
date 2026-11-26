// Package routing decides whether traffic goes to a silo (design §0.6): explicit, never assumed.
// Each service decides for itself (networking v2: one readiness gate per service, not per silo).
// A service says routeWhen: ready (only while the silo's readiness probe passes) or running (as
// soon as it runs). Without a readiness probe it is running, and the decision says it wasn't
// stated. Pure: every path traffic takes asks the same question here — the service's name (DNS),
// a Service's virtual IP and endpoints, a silo's own exposed ports and node ports, load-balancer
// backends, Ingress backends — and each turns "held" into its own absence: no DNS record, no
// endpoint, no outside rule, no backend, no route.
//
// Held never cuts what's already established: a silo that stops being ready keeps the
// connections it has (they end on their own); only new ones go elsewhere, or nowhere. That is
// unlike a lease ending (design §7.2d), which cuts them: a lease is access, readiness is load.
package routing

import (
	"slices"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Mode is the routeWhen in force for a service with this routeWhen in front of a silo with or
// without a readiness probe, whether it was stated, and what's wrong with it ("" if nothing):
// ready without a readiness probe, or nothing stated in front of one.
func Mode(routeWhen string, hasReadiness bool) (mode string, stated bool, problem string) {
	switch routeWhen {
	case "":
		if hasReadiness {
			return "", false, "routeWhen isn't stated and the silo has a readiness probe: say ready or running"
		}
		return v1.RouteWhenRunning, false, ""
	case v1.RouteWhenReady:
		if !hasReadiness {
			return v1.RouteWhenReady, true, "routeWhen: ready, and the silo has no readiness probe"
		}
	}
	return routeWhen, true, ""
}

func decide(routeWhen string, spec v1.SiloSpec, st v1.SiloStatus) v1.Routing {
	mode, stated, problem := Mode(routeWhen, spec.HasReadiness())
	r := v1.Routing{RouteWhen: mode, Stated: stated}
	ready := meta.FindCondition(st.Conditions, "Ready")
	since := func() *time.Time {
		if ready != nil && !ready.LastTransitionTime.IsZero() {
			t := ready.LastTransitionTime
			return &t
		}
		return nil
	}
	switch {
	case problem != "":
		r.Reason = problem
	case st.SiloIP == "" || (st.Phase != "" && st.Phase != "Running"):
		r.Reason, r.Since = "not running", since()
		if st.Phase != "" {
			r.Reason = "not running (" + st.Phase + ")"
		}
	case mode == v1.RouteWhenRunning:
		r.Routed = true
	case ready != nil && ready.Status == meta.ConditionTrue:
		r.Routed = true
	default:
		r.Reason, r.Since = "not ready", since()
		if ready != nil && ready.Message != "" {
			r.Reason += ": " + ready.Message
		}
	}
	return r
}

// Silo is whether a silo's own services (spec.services) get traffic now; nil if it has none.
// Each service decides by its own routeWhen (Services, in order); the silo's line is routed when
// every one is, and otherwise says the first held one and why.
func Silo(spec v1.SiloSpec, st v1.SiloStatus) *v1.Routing {
	return siloNamed("", spec, st)
}

// SiloNamed is Silo for the silo named name (it names its unnamed services).
func SiloNamed(name string, spec v1.SiloSpec, st v1.SiloStatus) *v1.Routing {
	return siloNamed(name, spec, st)
}

func siloNamed(name string, spec v1.SiloSpec, st v1.SiloStatus) *v1.Routing {
	if len(spec.Services) == 0 {
		return nil
	}
	var each []v1.Routing
	for _, sv := range spec.Services {
		r := decide(sv.RouteWhen, spec, st)
		r.Service = v1.ServiceNameOf(sv, name)
		each = append(each, r)
	}
	out := each[0]
	out.Service = ""
	someRouted := slices.ContainsFunc(each, func(r v1.Routing) bool { return r.Routed })
	for _, r := range each {
		if !r.Routed {
			out = r
			out.Service = ""
			if someRouted && r.Service != "" { // services disagree: say which one is held
				out.Reason = "service " + r.Service + ": " + r.Reason
			}
			break
		}
	}
	if len(each) > 1 {
		out.Services = each
	}
	return &out
}

// Service is whether the silo s's service named service gets traffic now, by its own routeWhen
// (ok false: s has no such service).
func Service(s *v1.Silo, service string) (r v1.Routing, ok bool) {
	for _, sv := range s.Spec.Services {
		if v1.ServiceNameOf(sv, s.Name) == service {
			r = decide(sv.RouteWhen, s.Spec, s.Status)
			r.Service = service
			return r, true
		}
	}
	return v1.Routing{}, false
}

// ServiceRouted reports whether traffic goes to s through its service named service now (false
// for a service it doesn't have).
func ServiceRouted(s *v1.Silo, service string) bool {
	r, ok := Service(s, service)
	return ok && r.Routed
}

// HeldServices are the names of s's services whose routeWhen holds traffic back now, in order.
func HeldServices(s *v1.Silo) []string {
	var out []string
	for _, sv := range s.Spec.Services {
		if r := decide(sv.RouteWhen, s.Spec, s.Status); !r.Routed {
			out = append(out, v1.ServiceNameOf(sv, s.Name))
		}
	}
	return out
}

// Routed reports whether traffic goes to s through every one of its own services now (true for a
// silo with no service: there is nothing to hold). Paths that know which service they serve ask
// ServiceRouted.
func Routed(s *v1.Silo) bool {
	r := SiloNamed(s.Name, s.Spec, s.Status)
	return r == nil || r.Routed
}

// Endpoint is whether svc sends to s now.
func Endpoint(svc *v1.Service, s *v1.Silo) v1.Routing {
	return decide(svc.Spec.RouteWhen, s.Spec, s.Status)
}

// CheckService is what admission says about a Service's routeWhen against the silos and sets it
// selects now (design §0.6): routeWhen: ready refused when a selected silo has no readiness probe,
// and a missing routeWhen refused when one has. Silos that come later can't be known at write
// time: they're held, with that reason (Endpoint). Pure.
func CheckService(svc *v1.Service, silos []*v1.Silo, sets []*v1.SiloSet) []string {
	var errs []string
	check := func(what string, spec v1.SiloSpec) {
		if _, _, problem := Mode(svc.Spec.RouteWhen, spec.HasReadiness()); problem != "" {
			errs = append(errs, what+": "+problem)
		}
	}
	for _, s := range silos {
		if s.Namespace == svc.Namespace && s.DeletionTimestamp == nil && v1.Selects(svc.Spec.Selector, s.Labels) {
			if setOf(s) != "" {
				continue // its set is checked as a whole
			}
			check("selects silo "+s.Name, s.Spec)
		}
	}
	for _, set := range sets {
		if set.Namespace == svc.Namespace && set.DeletionTimestamp == nil && v1.Selects(svc.Spec.Selector, set.Instance(0, false).Labels) {
			check("selects SiloSet "+set.Name+"'s instances", set.InstanceSpec())
		}
	}
	return errs
}

func setOf(s *v1.Silo) string { return s.Labels[v1.LabelSiloSet] }
