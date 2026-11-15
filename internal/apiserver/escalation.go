package apiserver

import (
	"context"
	"net/http"
	"reflect"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// checkEscalation: a role, or a binding, can't grant more than its author holds (design §0.8,
// audit K-016). A Role or ClusterRole's rules, and the rules of the role a binding names, must each
// be covered by the permissions the author has where the grant lands: the namespace for a Role
// and a RoleBinding, everywhere for a ClusterRole and a ClusterRoleBinding. A binding to a role
// that doesn't exist yet is refused too (a role made later would silently reach its subjects)
// unless the author holds everything. An update that leaves the rules (or roleRef and subjects)
// as stored grants nothing new and passes, so a label can change. The admin socket, the control
// plane and hosts are not asked: they have no roles (and the built-in admin holds * on *, which
// covers any rule). There is no `bind` verb: nobody can hand out what they don't hold.
func (s *Server) checkEscalation(ctx context.Context, t target, old, obj meta.Object) error {
	if t.status || s.auth == nil {
		return nil
	}
	user, isPerson := person(ctx)
	if !isPerson {
		return nil
	}
	if isNil(old) {
		old = nil
	}
	var ns string
	var rules []v1.PolicyRule
	var ref *v1.RoleRef
	switch o := obj.(type) {
	case *v1.Role:
		ns, rules = o.Namespace, o.Rules
		if p, ok := old.(*v1.Role); ok && reflect.DeepEqual(p.Rules, o.Rules) {
			return nil
		}
	case *v1.ClusterRole:
		rules = o.Rules
		if p, ok := old.(*v1.ClusterRole); ok && reflect.DeepEqual(p.Rules, o.Rules) {
			return nil
		}
	case *v1.RoleBinding:
		ns, ref = o.Namespace, &o.RoleRef
		if p, ok := old.(*v1.RoleBinding); ok && p.RoleRef == o.RoleRef && reflect.DeepEqual(p.Subjects, o.Subjects) {
			return nil
		}
	case *v1.ClusterRoleBinding:
		ref = &o.RoleRef
		if p, ok := old.(*v1.ClusterRoleBinding); ok && p.RoleRef == o.RoleRef && reflect.DeepEqual(p.Subjects, o.Subjects) {
			return nil
		}
	default:
		return nil
	}
	pol, err := s.policy.Policy(ctx)
	if err != nil {
		return err
	}
	groups := GroupsFrom(ctx)
	what := t.kind.Kind + " " + obj.GetObjectMeta().Name
	if ref != nil {
		var ok bool
		if rules, ok = pol.RulesOfRef(ns, *ref); !ok {
			if len(pol.Escalates(user, groups, ns, []v1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}}})) == 0 {
				return nil
			}
			return errf(http.StatusForbidden, "Forbidden", "%s: %s %s doesn't exist, and a binding to a role made later could grant anything: create the role first", what, ref.Kind, ref.Name)
		}
		what += " (" + ref.Kind + " " + ref.Name + ")"
	}
	if missing := pol.Escalates(user, groups, ns, rules); len(missing) > 0 {
		where := "in namespace " + ns
		if ns == "" {
			where = "cluster-wide"
		}
		return errf(http.StatusForbidden, "Forbidden", "%s would grant permissions you don't hold %s: %s", what, where, strings.Join(limited(missing, 6), "; "))
	}
	return nil
}

// limited keeps the first n entries, saying how many more there are.
func limited(l []string, n int) []string {
	if len(l) <= n {
		return l
	}
	return append(append([]string(nil), l[:n]...), "and more")
}
