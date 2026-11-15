package rbac

import (
	"fmt"
	"slices"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Roles can't grant more than their author holds (design §0.8, as in Kubernetes): creating or
// changing a role, or binding one, is refused when it would give a permission the author lacks.

// Held are the rules the user holds in namespace ns: every ClusterRoleBinding's role, and, for a
// namespace (ns != ""), the roles bound in it. ns "" is cluster-wide (only ClusterRoleBindings).
func (p *Policy) Held(user string, groups []string, ns string) []v1.PolicyRule {
	a := Attributes{User: user, Groups: groups}
	var out []v1.PolicyRule
	for _, b := range p.ClusterRoleBindings {
		if bound(b.Subjects, "", a) && b.RoleRef.Kind == "ClusterRole" {
			if cr := p.ClusterRoles[b.RoleRef.Name]; cr != nil {
				out = append(out, cr.Rules...)
			}
		}
	}
	if ns != "" {
		for _, b := range p.RoleBindings {
			if b.Namespace == ns && bound(b.Subjects, ns, a) {
				if rules, ok := p.rulesOf(b); ok {
					out = append(out, rules...)
				}
			}
		}
	}
	return out
}

// Missing lists the permissions in want that held doesn't cover, one entry per verb and resource
// ("verb resource", with the names or selector when the rule has them). Empty: nothing escalates.
// Every verb of a rule on every resource of it is checked on its own, so a user holding get and
// list in two rules covers a rule asking for both; a wildcard in want needs the same wildcard held.
func Missing(held, want []v1.PolicyRule) []string {
	var out []string
	for _, w := range want {
		for _, res := range w.Resources {
			for _, verb := range w.Verbs {
				if !covered(held, verb, res, w.ResourceNames, w.Selector) {
					out = append(out, describeAtom(verb, res, w.ResourceNames, w.Selector))
				}
			}
		}
	}
	return out
}

func describeAtom(verb, res string, names []string, sel map[string]string) string {
	s := verb + " " + res
	if len(names) > 0 {
		s += " (only " + strings.Join(names, ", ") + ")"
	}
	if len(sel) > 0 {
		s += fmt.Sprintf(" (selector %v)", sel)
	}
	return s
}

// covered: some held rule gives verb on res for every object the (names, selector) of the wanted
// rule reaches. Nothing wanted is narrower than a held rule's own limits: a rule held for a name
// or selector never covers a wider one.
func covered(held []v1.PolicyRule, verb, res string, names []string, sel map[string]string) bool {
	for _, h := range held {
		if !matchVerb(h.Verbs, verb, res) || !matchResource(h.Resources, res) {
			continue
		}
		if len(h.ResourceNames) > 0 {
			if len(names) == 0 || len(sel) > 0 {
				continue
			}
			ok := true
			for _, n := range names {
				if !slices.Contains(h.ResourceNames, n) {
					ok = false
				}
			}
			if !ok {
				continue
			}
		}
		if len(h.Selector) > 0 {
			// Every object the wanted rule reaches must match the held selector: the wanted one
			// states at least its entries, and doesn't reach by name.
			if len(names) > 0 {
				continue
			}
			ok := true
			for k, v := range h.Selector {
				if sel[k] != v {
					ok = false
				}
			}
			if !ok {
				continue
			}
		}
		return true
	}
	return false
}

// Escalates reports what a role's rules (or a binding's role) would grant the user beyond what
// they hold in ns.
func (p *Policy) Escalates(user string, groups []string, ns string, want []v1.PolicyRule) []string {
	return Missing(p.Held(user, groups, ns), want)
}

// RulesOfRef are the rules a binding in namespace ns (empty: cluster) grants through ref, and
// whether the role exists.
func (p *Policy) RulesOfRef(ns string, ref v1.RoleRef) ([]v1.PolicyRule, bool) {
	switch ref.Kind {
	case "Role":
		if r := p.Roles[ns+"/"+ref.Name]; r != nil && ns != "" {
			return r.Rules, true
		}
	case "ClusterRole":
		if r := p.ClusterRoles[ref.Name]; r != nil {
			return r.Rules, true
		}
	}
	return nil, false
}

// ClusterAdmin says whether user holds cluster-admin: every verb on every resource, cluster-wide
// (the built-in cluster-admin role, or one that grants as much). Some actions are a
// cluster-admin's by definition, whatever a role names (K-058: invites).
func (p *Policy) ClusterAdmin(user string, groups []string) bool {
	return len(Missing(p.Held(user, groups, ""), []v1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}}})) == 0
}
