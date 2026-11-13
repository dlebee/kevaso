package provider

import (
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/leases"
)

// sources are where clients may reach each exposed port of s from (design §7.2d): the service's
// loadBalancer.allowFrom (nil: anywhere), narrowed by lease.allowFrom on its leased ports. An
// empty, non-nil list: no source may (the two don't overlap).
func sources(s *v1.Silo) map[string][]string {
	sv := s.Spec.Service
	var base []string
	if sv.LoadBalancer != nil {
		base = sv.LoadBalancer.AllowFrom
	}
	out := map[string][]string{}
	for _, p := range sv.Ports {
		out[p.Name] = base
	}
	if sv.Lease != nil && len(sv.Lease.AllowFrom) > 0 {
		narrow := leases.Sources(base, sv.Lease.AllowFrom)
		for _, p := range leases.Leased(sv) {
			out[p] = narrow
		}
	}
	return out
}

// leased: which of s's leased ports are closed now (no backend on its load balancer), and when its
// next lease ends (zero: none).
func (c *Balancers) leased(s *v1.Silo) ([]string, time.Time) {
	if s.Spec.Service == nil || s.Spec.Service.Lease == nil {
		return nil, time.Time{}
	}
	var all []*v1.Lease
	if c.Leases != nil {
		for _, o := range c.Leases.List() {
			if l := o.(*v1.Lease); l.Namespace == s.Namespace && l.Spec.Silo == s.Name {
				all = append(all, l)
			}
		}
	}
	now := c.now()
	return leases.Closed(s, all, now), leases.Next(all, now)
}
