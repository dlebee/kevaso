package apiserver

import (
	"context"
	"errors"
	"net/http"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/claims"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

// claimAddedHostPorts takes, on the silo's host, every host port the update adds or whose number
// changes, before the write. A port another silo holds is a 409 naming the holder, and any port
// this call just took is put back. An unplaced silo claims nothing here: placement does. The
// version is the write's resourceVersion; an empty one would stick the claim forever.
func (s *Server) claimAddedHostPorts(ctx context.Context, old, admitted meta.Object, version string) (func(), error) {
	prev, ok1 := old.(*v1.Silo)
	next, ok2 := admitted.(*v1.Silo)
	if !ok1 || !ok2 || prev.Status.Host == "" {
		return nil, nil
	}
	added := scheduler.AddedHostPorts(prev.Spec, next.Spec)
	if len(added) == 0 {
		return nil, nil
	}
	if version == "" || prev.UID == "" {
		return nil, errf(http.StatusConflict, "Conflict", "%s/%s: a host port is claimed against the object's resourceVersion", next.Namespace, next.Name)
	}
	as := *prev
	as.ResourceVersion = version
	cl := &claims.Claims{Store: s.store}
	held, err := siloctl.ClaimNewHostPorts(ctx, cl, &as, prev.Status.Host, added)
	if err != nil {
		if errors.Is(err, claims.ErrBusy) {
			return nil, errf(http.StatusConflict, "Conflict", "%s/%s: a host port was changing; try again", next.Namespace, next.Name)
		}
		return nil, err
	}
	if len(held) > 0 {
		return nil, errf(http.StatusConflict, "Conflict", "%s/%s: %s", next.Namespace, next.Name, joinMessages(held))
	}
	uid, host := prev.UID, prev.Status.Host
	return func() { siloctl.ReleaseHostPorts(ctx, cl, uid, host, added) }, nil
}

// checkClusterHostPorts refuses a host port whose number a host in the cluster listens on, beyond
// the fixed set checkPorts already refuses (an SSH port that is not 22, a mesh listen port, an API
// or etcd port a host publishes). The fixed set is the same on every host; these are this
// cluster's.
func (s *Server) checkClusterHostPorts(ctx context.Context, t target, obj meta.Object) error {
	spec, ok := hostPortSpec(obj)
	if !ok || !asksHostPort(spec) {
		return nil
	}
	objs, _, err := s.store.List(ctx, store.Selector{Kind: "Host"})
	if err != nil {
		return err
	}
	extra := map[int]string{}
	for _, o := range objs {
		h, _, err := v1.Decode(o.Data)
		if err != nil {
			continue
		}
		host, ok := h.(*v1.Host)
		if !ok {
			continue
		}
		for n, why := range host.ExtraReservedPorts() {
			if _, seen := extra[n]; !seen {
				extra[n] = why
			}
		}
	}
	for _, p := range spec.Open() {
		if len(p.HostPort) == 0 {
			continue
		}
		if why, ok := extra[p.HostNumber()]; ok { // a host in the cluster listens here
			where := t.kind.Kind + " " + obj.GetObjectMeta().Name
			if t.kind.Kind == "SiloSet" {
				where += " template"
			}
			return errf(http.StatusUnprocessableEntity, "Invalid", "%s: port %d is %s, which a silo may not take", where, p.HostNumber(), why)
		}
	}
	return nil
}

func hostPortSpec(obj meta.Object) (v1.SiloSpec, bool) {
	switch o := obj.(type) {
	case *v1.Silo:
		return o.Spec, true
	case *v1.SiloSet:
		return o.Spec.Template.SiloSpec, true
	default:
		return v1.SiloSpec{}, false
	}
}

func asksHostPort(spec v1.SiloSpec) bool {
	for _, p := range spec.Open() {
		if len(p.HostPort) > 0 {
			return true
		}
	}
	return false
}
