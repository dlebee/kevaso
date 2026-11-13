package provider

import (
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/leases"
)

// sources are where clients may reach each exposed port of s from (design §7.2d): the service's
// loadBalancer.allowFrom (nil: anywhere), narrowed on each leased port by its own lease.allowFrom.
// An empty, non-nil list: no source may (the two don't overlap).
func sources(s *v1.Silo) map[string][]string {
	sv := s.Spec.Service
	base := leases.ServiceSources(sv)
	narrow := leases.PortSources(sv)
	out := map[string][]string{}
	for _, p := range sv.Ports {
		out[p.Name] = base
		if n, ok := narrow[p.Name]; ok {
			out[p.Name] = n
		}
	}
	return out
}

// leased: which of s's leased ports are closed now (no backend on its load balancer), and when its
// next lease ends (zero: none).
func (c *LoadBalancers) leased(s *v1.Silo) ([]string, time.Time) {
	if !leases.Any(s.Spec.Service) {
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
