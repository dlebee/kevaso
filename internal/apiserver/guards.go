package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Guards (ADR 0005 §9a): the built-in checks that stand for a privilege — exposing silos publicly,
// publishing on a public ingress class, using secrets through grants — and the ones that refuse
// what a runtime or its storage can't do. They run on the object as it will be stored: after
// schema defaults and mutation policies, before the kind's CEL rules and validation policies. So a
// mutation policy can't get a write past them: whatever it changes is checked as if the writer
// had sent it.

// The same holds for the checks on what can't change and on a KindDefinition's names: a policy
// could otherwise rewrite an Image's version or shadow a built-in kind after they were checked.

// guard runs every built-in guard on a main-resource write (status writes don't change the spec).
// old is nil on create.
func (s *Server) guard(ctx context.Context, t target, old, obj meta.Object) error {
	if t.status {
		return nil
	}
	if !isNil(old) {
		if errs := transition(old, obj); len(errs) > 0 {
			return errf(http.StatusUnprocessableEntity, "Invalid", "%s %s: %s", t.kind.Kind, obj.GetObjectMeta().Name, joinMessages(errs))
		}
	}
	if d, ok := obj.(*v1.KindDefinition); ok {
		prev, _ := old.(*v1.KindDefinition)
		if err := s.checkDefinition(ctx, d, prev); err != nil {
			return err
		}
	}
	for _, check := range []func(context.Context, target, meta.Object) error{
		s.checkExposure,
		s.checkPublishPublic,
		s.checkSecretUse,
		s.checkRuntimeFit,
		s.checkIPs,
		func(_ context.Context, t target, obj meta.Object) error { return s.checkMovability(t, obj) },
		func(_ context.Context, t target, obj meta.Object) error { return s.checkLease(t, obj) },
	} {
		if err := check(ctx, t, obj); err != nil {
			return err
		}
	}
	return nil
}

// privileges sums up what the guards look at in an object: how it exposes silos, which ingress
// class it's on, which grants a silo has and which secrets a grant names.
func privileges(obj meta.Object) string {
	p := exposure(obj)
	switch o := obj.(type) {
	case *v1.Silo:
		g := slices.Clone(o.Spec.Grants)
		slices.Sort(g)
		p += fmt.Sprint("|grants:", g)
	case *v1.SiloSet:
		g := slices.Clone(o.Spec.Template.Grants)
		slices.Sort(g)
		p += fmt.Sprint("|grants:", g)
	case *v1.Grant:
		p += "|uses:" + fmt.Sprint(grantUses(o))
	case *v1.Ingress:
		p += "|class:" + o.Spec.IngressClass
	}
	return p + namedIPs(obj)
}

// checkMutatedPrivileges refuses what a mutation policy changed about privileges on a write by a
// caller the guards don't ask RBAC about (the admin socket, kevasod's own controllers, hosts): for
// them a guard has nobody to check, so a policy must not hand them anything new. A person's write
// needs nothing here: the guards check them on the object as mutated.
func (s *Server) checkMutatedPrivileges(ctx context.Context, t target, before string, obj meta.Object) error {
	if s.auth == nil {
		return nil
	}
	if _, isPerson := person(ctx); isPerson {
		return nil
	}
	if after := privileges(obj); after != before {
		return errf(http.StatusForbidden, "Forbidden", "%s %s: mutation policies changed what it exposes or which secrets it uses (%s → %s), on a write by the control plane: policies can't grant privileges",
			t.kind.Kind, obj.GetObjectMeta().Name, before, after)
	}
	return nil
}

// checkMutatedSecretValue: a secret's value is taken out before policies run (it's sealed, never
// stored); a policy that sets one would store it in the clear.
func checkMutatedSecretValue(obj meta.Object) error {
	if sec, ok := obj.(*v1.Secret); ok && sec.Spec.Value != nil {
		return errf(http.StatusUnprocessableEntity, "Invalid", "Secret %s: a mutation policy set spec.value: values are never set by policies", sec.Name)
	}
	return nil
}

// namedIPs are the IPs an object names, for privileges: naming one needs use on it.
func namedIPs(obj meta.Object) string {
	switch o := obj.(type) {
	case *v1.Silo:
		if sv := o.Spec.Service; sv != nil && sv.LoadBalancer != nil && sv.LoadBalancer.IP != "" || o.Spec.Network.Egress.IP != "" {
			return "|ips:" + fmt.Sprint(v1.SiloIPs(o))
		}
	case *v1.Service:
		if o.Spec.LoadBalancerIP != "" {
			return "|ips:" + o.Spec.LoadBalancerIP
		}
	}
	return ""
}
