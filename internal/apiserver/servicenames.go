package apiserver

import (
	"context"
	"net/http"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/names"
)

// checkServiceName refuses a service name someone else in the namespace holds (design §7.0: one
// name, one owner), saying who: a silo's service (service.name, or the silo's own name), a
// standalone Service, and a SiloSet's instances (named NAME-0, NAME-1… each) alike.
func (s *Server) checkServiceName(ctx context.Context, t target, obj meta.Object) error {
	var want []string
	self := ""
	switch o := obj.(type) {
	case *v1.Silo:
		if n := v1.ServiceName(o); n != "" {
			want, self = []string{n}, "silo/"+o.Name
		}
	case *v1.Service:
		want, self = []string{o.Name}, "service/"+o.Name
	case *v1.SiloSet:
		if o.Spec.Template.Service != nil {
			for i := 0; i < o.Spec.Instances+o.Spec.Standby; i++ {
				want = append(want, v1.InstanceName(o.Name, i))
			}
		}
	}
	if len(want) == 0 {
		return nil
	}
	silos, svcs, err := s.silosAndServices(ctx, t.namespace)
	if err != nil {
		return err
	}
	for _, n := range want {
		who := names.Holder(t.namespace, n, self, silos, svcs)
		if set, ok := obj.(*v1.SiloSet); ok && who == "silo/"+n && ownedBySet(silos, n, set) {
			continue // its own instance
		}
		if who != "" {
			return errf(http.StatusConflict, "NameTaken", "%s %s: the service name %s is %s's in namespace %s (a name has one owner: pick another service.name, or put both behind one Service)",
				t.kind.Kind, obj.GetObjectMeta().Name, n, who, t.namespace)
		}
	}
	return nil
}

func ownedBySet(silos []*v1.Silo, name string, set *v1.SiloSet) bool {
	for _, x := range silos {
		if x.Name == name && x.Labels[v1.LabelSiloSet] == set.Name {
			return true
		}
	}
	return false
}
