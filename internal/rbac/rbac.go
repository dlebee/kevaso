// Package rbac decides who may do what, Kubernetes-style (design §9.3): pure evaluation over a
// snapshot of Roles, ClusterRoles and their bindings. No binding, no access.
package rbac

import (
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Group every signed-in identity has.
const Authenticated = "system:authenticated"

// ClusterAdmins is the group the built-in cluster-admin binding grants to (kvoadm's admin
// certificates are in it).
const ClusterAdmins = "kevaso:cluster-admins"

// ServiceAccountUser is how a service account appears as a user.
func ServiceAccountUser(namespace, name string) string {
	return "system:serviceaccount:" + namespace + ":" + name
}

// Attributes is one request, in RBAC terms.
type Attributes struct {
	User      string
	Groups    []string
	Verb      string // get, list, watch, create, update, delete, …
	Resource  string // plural, with the subresource: silos, silos/status, silos/exec
	Namespace string // "" for cluster-scoped kinds and cluster-wide lists
	Name      string // "" for lists and creates
}

func (a Attributes) String() string {
	where := ""
	if a.Namespace != "" {
		where = " in namespace " + a.Namespace
	}
	what := a.Resource
	if a.Name != "" {
		what += "/" + a.Name
	}
	return fmt.Sprintf("%s %s%s", a.Verb, what, where)
}

// Decision is the answer and why.
type Decision struct {
	Allowed bool
	Reason  string
}

// Policy is a snapshot of every role and binding.
type Policy struct {
	Roles               map[string]*v1.Role // by "namespace/name"
	ClusterRoles        map[string]*v1.ClusterRole
	RoleBindings        []*v1.RoleBinding
	ClusterRoleBindings []*v1.ClusterRoleBinding
}

// NewPolicy builds a snapshot from objects of the four kinds (others are ignored).
func NewPolicy(objs []meta.Object) *Policy {
	p := &Policy{Roles: map[string]*v1.Role{}, ClusterRoles: map[string]*v1.ClusterRole{}}
	for _, o := range objs {
		switch o := o.(type) {
		case *v1.Role:
			p.Roles[o.Namespace+"/"+o.Name] = o
		case *v1.ClusterRole:
			p.ClusterRoles[o.Name] = o
		case *v1.RoleBinding:
			p.RoleBindings = append(p.RoleBindings, o)
		case *v1.ClusterRoleBinding:
			p.ClusterRoleBindings = append(p.ClusterRoleBindings, o)
		}
	}
	return p
}

// Authorize decides one request.
func (p *Policy) Authorize(a Attributes) Decision {
	for _, b := range p.ClusterRoleBindings {
		if !bound(b.Subjects, "", a) || b.RoleRef.Kind != "ClusterRole" {
			continue
		}
		if cr := p.ClusterRoles[b.RoleRef.Name]; cr != nil && allows(cr.Rules, a) {
			return Decision{true, fmt.Sprintf("ClusterRoleBinding %s (ClusterRole %s)", b.Name, cr.Name)}
		}
	}
	if a.Namespace != "" {
		for _, b := range p.RoleBindings {
			if b.Namespace != a.Namespace || !bound(b.Subjects, b.Namespace, a) {
				continue
			}
			if rules, ok := p.rulesOf(b); ok && allows(rules, a) {
				return Decision{true, fmt.Sprintf("RoleBinding %s/%s (%s %s)", b.Namespace, b.Name, b.RoleRef.Kind, b.RoleRef.Name)}
			}
		}
	}
	// Anyone with a role in a namespace may see that namespace itself.
	if a.Resource == "namespaces" && a.Name != "" && (a.Verb == "get" || a.Verb == "watch") && p.hasBindingIn(a.Name, a) {
		return Decision{true, "has a role in namespace " + a.Name}
	}
	return Decision{false, fmt.Sprintf("no role lets %s %s", a.User, a)}
}

// NamespacesFor lists the namespaces where the user has any RoleBinding (for listing namespaces to
// someone who can't list them all).
func (p *Policy) NamespacesFor(a Attributes) []string {
	var out []string
	for _, b := range p.RoleBindings {
		if bound(b.Subjects, b.Namespace, a) && !slices.Contains(out, b.Namespace) {
			out = append(out, b.Namespace)
		}
	}
	slices.Sort(out)
	return out
}

func (p *Policy) hasBindingIn(ns string, a Attributes) bool {
	return slices.Contains(p.NamespacesFor(a), ns)
}

func (p *Policy) rulesOf(b *v1.RoleBinding) ([]v1.PolicyRule, bool) {
	switch b.RoleRef.Kind {
	case "Role":
		if r := p.Roles[b.Namespace+"/"+b.RoleRef.Name]; r != nil {
			return r.Rules, true
		}
	case "ClusterRole":
		if r := p.ClusterRoles[b.RoleRef.Name]; r != nil {
			return r.Rules, true
		}
	}
	return nil, false
}

func bound(subjects []v1.Subject, bindingNS string, a Attributes) bool {
	for _, s := range subjects {
		switch s.Kind {
		case "User":
			if s.Name == a.User {
				return true
			}
		case "Group":
			if slices.Contains(a.Groups, s.Name) {
				return true
			}
		case "ServiceAccount":
			ns := s.Namespace
			if ns == "" {
				ns = bindingNS
			}
			if ServiceAccountUser(ns, s.Name) == a.User {
				return true
			}
		}
	}
	return false
}

func allows(rules []v1.PolicyRule, a Attributes) bool {
	for _, r := range rules {
		if match(r.Verbs, a.Verb) && matchResource(r.Resources, a.Resource) &&
			(len(r.ResourceNames) == 0 || (a.Name != "" && slices.Contains(r.ResourceNames, a.Name))) {
			return true
		}
	}
	return false
}

func match(list []string, v string) bool {
	return slices.Contains(list, "*") || slices.Contains(list, v)
}

// matchResource: "*" is everything, "silos" isn't "silos/exec", "*/status" is every status.
func matchResource(list []string, res string) bool {
	for _, r := range list {
		if r == "*" || r == res {
			return true
		}
		if strings.HasPrefix(r, "*/") && strings.HasSuffix(res, r[1:]) {
			return true
		}
	}
	return false
}
