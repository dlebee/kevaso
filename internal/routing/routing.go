// Package routing decides whether traffic goes to a silo (design §0.6): explicit, never assumed.
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

// Silo is whether a silo's own service (spec.service) gets traffic now; nil if it has none.
func Silo(spec v1.SiloSpec, st v1.SiloStatus) *v1.Routing {
	if spec.Service == nil {
		return nil
	}
	r := decide(spec.Service.RouteWhen, spec, st)
	return &r
}

// Routed reports whether traffic goes to s through its own service now (true for a silo with no
// service: there is nothing to hold).
func Routed(s *v1.Silo) bool {
	r := Silo(s.Spec, s.Status)
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
