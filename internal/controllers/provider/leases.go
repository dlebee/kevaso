package provider

import (
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/leases"
)

// leased: which of s's leased ports are closed now (no backend on its load balancer), and when its
// next lease ends (zero: none).
func (c *LoadBalancers) leased(s *v1.Silo) ([]string, time.Time) {
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
