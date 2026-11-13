package apiserver

import (
	"context"
	"net/http"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/routing"
	"kevaso.com/core/internal/store"
)

// checkRouting: a Service's routeWhen against the silos it selects now (design §0.6). ready is
// refused in front of a silo without a readiness probe, and a missing routeWhen in front of one
// with. A silo's own service is checked with its spec (semantic). Silos written later aren't
// refused for a Service's sake: its endpoints show them held, with the reason.
func (s *Server) checkRouting(ctx context.Context, t target, obj meta.Object) error {
	svc, ok := obj.(*v1.Service)
	if !ok || t.status {
		return nil
	}
	var silos []*v1.Silo
	var sets []*v1.SiloSet
	for kind, add := range map[string]func(meta.Object){
		"Silo":    func(o meta.Object) { silos = append(silos, o.(*v1.Silo)) },
		"SiloSet": func(o meta.Object) { sets = append(sets, o.(*v1.SiloSet)) },
	} {
		objs, _, err := s.store.List(ctx, store.Selector{Kind: kind, Namespace: t.namespace})
		if err != nil {
			return err
		}
		for _, o := range objs {
			if d, _, err := v1.Decode(o.Data); err == nil {
				add(d)
			}
		}
	}
	if errs := routing.CheckService(svc, silos, sets); len(errs) > 0 {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Service %s: %s", svc.Name, joinMessages(errs))
	}
	return nil
}
