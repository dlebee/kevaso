package worker

import (
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kni"
	"kevaso.com/core/internal/leases"
)

// WithLeases marks this host's silos' leased ports (design §7.2d): which are closed at now (no
// outside rule) and, for open ones, their sources (the service's allowFrom narrowed by the lease's).
// Pure: the same view, silos, leases and moment give the same rules.
func WithLeases(view kni.Host, silos []*v1.Silo, all []*v1.Lease, now time.Time) kni.Host {
	byKey := map[string]*v1.Silo{}
	for _, s := range silos {
		byKey[s.Namespace+"/"+s.Name] = s
	}
	local := make([]kni.Silo, len(view.Local))
	copy(local, view.Local)
	for i, ks := range local {
		s, ok := byKey[ks.Key]
		if !ok || s.Spec.Service == nil || s.Spec.Service.Lease == nil {
			continue
		}
		sv := s.Spec.Service
		ks.Leased = leases.Leased(sv)
		ks.Closed = leases.Closed(s, all, now)
		if len(sv.Lease.AllowFrom) > 0 {
			var base []string
			switch {
			case sv.Expose == v1.ExposeHostPort && sv.HostPort != nil:
				base = sv.HostPort.AllowFrom
			case sv.Expose == v1.ExposeLoadBalancer && sv.LoadBalancer != nil:
				base = sv.LoadBalancer.AllowFrom
			}
			ks.LeaseFrom = leases.Sources(base, sv.Lease.AllowFrom)
		}
		local[i] = ks
	}
	view.Local = local
	return view
}

// leaseTimer fires at the next lease end after now (never, if there's none): the host closes a
// port at its time even if nothing else changes.
func leaseTimer(all []*v1.Lease, now time.Time) (<-chan time.Time, func()) {
	next := leases.Next(all, now)
	if next.IsZero() {
		return nil, func() {}
	}
	t := time.NewTimer(next.Sub(now) + 10*time.Millisecond)
	return t.C, func() { t.Stop() }
}
