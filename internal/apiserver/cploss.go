package apiserver

import (
	"context"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// ControlPlaneLossWarning is what a silo with onControlPlaneLoss: Stop is told when the cluster
// has exactly one system node (design §0.7).
func ControlPlaneLossWarning(kind, name string) string {
	return kind + " " + name + ": onControlPlaneLoss: Stop, and this cluster has exactly one system node: " +
		"the silo will stop whenever that node is unreachable (a reboot, a network blip, a control plane " +
		"on a laptop that travels). Use it only where the control plane is always reachable, i.e. with more than one system node"
}

// checkControlPlaneLoss warns when a silo (or a SiloSet's template) says Stop and the cluster has
// one system node. Never refuses: the field's values are validated with the silo (semantic).
func (s *Server) checkControlPlaneLoss(ctx context.Context, t target, obj meta.Object) error {
	if t.status {
		return nil
	}
	var av v1.Availability
	switch o := obj.(type) {
	case *v1.Silo:
		av = o.Spec.Availability
	case *v1.SiloSet:
		av = o.Spec.Template.Availability
	default:
		return nil
	}
	if stops, _ := av.StopsOnControlPlaneLoss(); !stops {
		return nil
	}
	hosts, err := listAs[*v1.Host](ctx, s.store, "Host")
	if err != nil {
		return nil
	}
	n := 0
	for _, h := range hosts {
		if cp := h.Spec.Components.ControlPlane; cp != nil && !cp.StateOnly {
			n++
		}
	}
	if n == 1 {
		warn(ctx, ControlPlaneLossWarning(t.kind.Kind, obj.GetObjectMeta().Name))
	}
	return nil
}
