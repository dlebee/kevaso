package rbac

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The built-in roles' full matrix (design §9.3), written out here independently of builtin.go:
// every verb on every resource and subresource, for each role bound in a namespace. A change to a
// built-in role changes this table on purpose, or it's a bug.

var (
	allVerbs     = []string{"get", "list", "watch", "create", "update", "patch", "delete", v1.VerbUse, v1.VerbReadValue, v1.VerbWrite, v1.VerbApprove, v1.VerbOpen}
	allResources = []string{
		"silos", "silosets", "services", "vmimages", "serviceaccounts", "grants", "ingresses", "certificates",
		"silos/status", "silos/exec", "silos/move", "silos/ssh", "silos/files", v1.ResourceExposure, "silosets/scale",
		"serviceaccounts/token", "services/expose-public", "ingresses/publish-public",
		"secrets", "approvals", "panes", "leases", "ips", "roles", "rolebindings", "runs",
		"hosts", "namespaces", "clusterroles", "clusterrolebindings", "kinddefinitions", "validationpolicies", "plugins", "issuers", "ingressclasses",
	}
	rw        = []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	ro        = []string{"get", "list", "watch"}
	workloadR = []string{"silos", "silosets", "services", "vmimages", "serviceaccounts", "grants", "ingresses", "certificates"}
)

// grants is a role's spec: resource → the verbs it allows (secrets' list and write aliases
// expanded: list → get, list, watch; write → create, update, patch, delete).
type grants map[string][]string

func (g grants) add(verbs []string, res ...string) grants {
	for _, r := range res {
		g[r] = append(g[r], verbs...)
	}
	return g
}

func expected() map[string]grants {
	secretsMeta := append([]string{"list"}, ro...)
	secretsWrite := []string{v1.VerbWrite, "create", "update", "patch", "delete"}
	return map[string]grants{
		"admin": grants{}.add(rw, append(slices.Clone(workloadR), "roles", "rolebindings")...).
			add([]string{"create"}, "silos/exec", "silos/move", "serviceaccounts/token", "services/expose-public", "ingresses/publish-public", "silos/ssh").
			add([]string{"get", "create"}, "silos/files").
			add(slices.Concat(secretsMeta, secretsWrite, []string{v1.VerbUse, v1.VerbReadValue, v1.VerbApprove}), "secrets").
			add([]string{"get", "list", "watch", "delete"}, "approvals", "panes", "leases").
			add([]string{v1.VerbOpen, v1.VerbApprove}, v1.ResourceExposure).
			add(append(slices.Clone(rw), v1.VerbUse), "ips"),
		"editor": grants{}.add(rw, workloadR...).
			add([]string{"create"}, "silos/exec", "silos/move", "serviceaccounts/token", "silos/ssh").
			add([]string{"get", "create"}, "silos/files").
			add(slices.Concat(secretsMeta, secretsWrite, []string{v1.VerbUse}), "secrets").
			add(ro, "approvals", "panes", "leases").
			add([]string{v1.VerbOpen}, v1.ResourceExposure).
			add(append(slices.Clone(ro), v1.VerbUse), "ips"),
		"viewer": grants{}.add(ro, workloadR...).
			add(secretsMeta, "secrets").
			add(ro, "approvals", "panes", "leases", "ips"),
		"runner": grants{}.add([]string{"get", "list", "watch", "create"}, "runs"),
	}
}

func builtinPolicy(extra ...meta.Object) *Policy {
	var objs []meta.Object
	for _, r := range BuiltinRoles() {
		objs = append(objs, r)
	}
	for _, b := range BuiltinBindings() {
		objs = append(objs, b)
	}
	return NewPolicy(append(objs, extra...))
}

func TestBuiltinRoleMatrix(t *testing.T) {
	want := expected()
	var bindings []meta.Object
	for role := range want {
		bindings = append(bindings, &v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role, Namespace: "d"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: role + "-user"}}})
	}
	p := builtinPolicy(bindings...)
	for role, g := range want {
		for _, res := range allResources {
			for _, verb := range allVerbs {
				a := Attributes{User: role + "-user", Groups: []string{Authenticated}, Verb: verb, Resource: res, Namespace: "d", Name: "x", Labels: map[string]string{}}
				got := p.Authorize(a).Allowed
				w := slices.Contains(g[res], verb)
				if res == "namespaces" && a.Name == "x" {
					w = false // their own namespace only (below)
				}
				if got != w {
					t.Errorf("%s: %s %s in d: %v, want %v", role, verb, res, got, w)
				}
				// The same request in another namespace, or cluster-wide: never.
				for _, ns := range []string{"other", ""} {
					b := a
					b.Namespace = ns
					if p.Authorize(b).Allowed {
						t.Errorf("%s (bound in d): %s %s in %q allowed", role, verb, res, ns)
					}
				}
			}
		}
		// Everyone with a role in d sees d, and only see it.
		for _, verb := range allVerbs {
			got := p.Authorize(Attributes{User: role + "-user", Verb: verb, Resource: "namespaces", Name: "d"}).Allowed
			if want := verb == "get" || verb == "watch"; got != want {
				t.Errorf("%s: %s namespace d: %v, want %v", role, verb, got, want)
			}
		}
	}
	// cluster-admin, through the cluster-admins group: everything, everywhere.
	for _, res := range allResources {
		for _, verb := range allVerbs {
			for _, ns := range []string{"d", ""} {
				if !p.Authorize(Attributes{User: "root", Groups: []string{ClusterAdmins}, Verb: verb, Resource: res, Namespace: ns}).Allowed {
					t.Errorf("cluster-admin: %s %s in %q refused", verb, res, ns)
				}
			}
		}
	}
}

// approve, on secrets or on silos/exposure, is only ever an admin's (and cluster-admin's).
func TestOnlyAdminsApprove(t *testing.T) {
	for _, r := range BuiltinRoles() {
		for _, rule := range r.Rules {
			if (slices.Contains(rule.Verbs, v1.VerbApprove) || slices.Contains(rule.Verbs, "*")) && r.Name != "admin" && r.Name != "cluster-admin" {
				t.Errorf("built-in role %s can approve %v", r.Name, rule.Resources)
			}
		}
	}
}

// A role without a verb is refused it. Random single-rule roles: a rule allows exactly its verbs
// (and on secrets, list and write's aliases) on exactly its resources (a subresource only when
// named, or by */SUB), with resourceNames and selectors narrowing, never widening.
func TestPropertyARuleAllowsOnlyWhatItSays(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	resources := append(slices.Clone(allResources), "*", "*/status", "*/exec")
	verbs := append(slices.Clone(allVerbs), "*")
	runs := 500
	if testing.Short() {
		runs = 60
	}
	for i := 0; i < runs; i++ {
		rule := v1.PolicyRule{Verbs: pickSome(r, verbs, 3), Resources: pickSome(r, resources, 2)}
		if r.Intn(4) == 0 {
			rule.ResourceNames = []string{"api"}
		}
		if r.Intn(5) == 0 {
			rule.Selector = map[string]string{"tier": "a"}
		}
		p := NewPolicy([]meta.Object{
			&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "r", Namespace: "d"}, Rules: []v1.PolicyRule{rule}},
			&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "d"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "r"},
				Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "bot"}}},
		})
		for _, res := range allResources {
			for _, verb := range allVerbs {
				for _, name := range []string{"", "api", "db"} {
					for _, labels := range []map[string]string{nil, {"tier": "a"}, {"tier": "b"}} {
						a := Attributes{User: ServiceAccountUser("d", "bot"), Verb: verb, Resource: res, Namespace: "d", Name: name, Labels: labels}
						got := p.Authorize(a).Allowed
						want := ruleSays(rule, a)
						if got != want {
							t.Fatalf("rule %+v: %s %s/%s labels %v: %v, want %v", rule, verb, res, name, labels, got, want)
						}
						// Another service account named bot, elsewhere, gets nothing.
						a.User = ServiceAccountUser("other", "bot")
						if p.Authorize(a).Allowed {
							t.Fatalf("rule %+v: other/bot allowed %s %s", rule, verb, res)
						}
					}
				}
			}
		}
	}
}

func pickSome(r *rand.Rand, from []string, max int) []string {
	n := 1 + r.Intn(max)
	var out []string
	for _, i := range r.Perm(len(from))[:n] {
		out = append(out, from[i])
	}
	return out
}

// ruleSays is the spec of one rule, written apart from rbac.go.
func ruleSays(rule v1.PolicyRule, a Attributes) bool {
	verbOK := slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Verbs, a.Verb)
	if !verbOK && a.Resource == "secrets" {
		switch a.Verb {
		case "get", "watch":
			verbOK = slices.Contains(rule.Verbs, "list")
		case "create", "update", "patch", "delete":
			verbOK = slices.Contains(rule.Verbs, v1.VerbWrite)
		}
	}
	resOK := false
	for _, r := range rule.Resources {
		_, sub, hasSub := strings.Cut(a.Resource, "/")
		switch {
		case r == "*", r == a.Resource:
			resOK = true
		case strings.HasPrefix(r, "*/") && hasSub && r[2:] == sub:
			resOK = true
		}
	}
	nameOK := len(rule.ResourceNames) == 0 || (a.Name != "" && slices.Contains(rule.ResourceNames, a.Name))
	selOK := len(rule.Selector) == 0 || (a.Name != "" && a.Labels != nil && a.Labels["tier"] == rule.Selector["tier"])
	return verbOK && resOK && nameOK && selOK
}

// A binding's subjects: a User is that user only, a Group its members, a ServiceAccount that
// account in its namespace (the binding's by default); nothing matches by prefix or case.
func TestSubjectsMatchExactly(t *testing.T) {
	p := NewPolicy([]meta.Object{
		&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "r", Namespace: "d"}, Rules: []v1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"silos"}}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "d"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "r"},
			Subjects: []v1.Subject{{Kind: "User", Name: "bob"}, {Kind: "Group", Name: "ops"}, {Kind: "ServiceAccount", Name: "ci"}, {Kind: "ServiceAccount", Name: "deploy", Namespace: "tools"}}},
	})
	for _, c := range []struct {
		user   string
		groups []string
		want   bool
	}{
		{"bob", nil, true}, {"Bob", nil, false}, {"bobby", nil, false}, {"bo", nil, false},
		{"x", []string{"ops"}, true}, {"x", []string{"Ops"}, false}, {"ops", nil, false},
		{ServiceAccountUser("d", "ci"), nil, true}, {ServiceAccountUser("other", "ci"), nil, false},
		{ServiceAccountUser("tools", "deploy"), nil, true}, {ServiceAccountUser("d", "deploy"), nil, false},
		{"ci", nil, false}, {"system:serviceaccount:d:ci:x", nil, false},
		{"", nil, false}, {"", []string{""}, false},
	} {
		got := p.Authorize(Attributes{User: c.user, Groups: c.groups, Verb: "get", Resource: "silos", Namespace: "d", Name: "a"}).Allowed
		if got != c.want {
			t.Errorf("%q %v: %v, want %v", c.user, c.groups, got, c.want)
		}
	}
}

// A ClusterRoleBinding to anything but a ClusterRole grants nothing; a RoleBinding to a Role in
// another namespace grants nothing.
func TestBindingsReachOnlyTheirRoles(t *testing.T) {
	rules := []v1.PolicyRule{{Verbs: []string{"*"}, Resources: []string{"*"}}}
	p := NewPolicy([]meta.Object{
		&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "all", Namespace: "other"}, Rules: rules},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "b", Namespace: "d"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "all"}, Subjects: []v1.Subject{{Kind: "User", Name: "u"}}},
		&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "all"}, Rules: rules},
		&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "c"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "all"}, Subjects: []v1.Subject{{Kind: "User", Name: "v"}}},
	})
	for _, u := range []string{"u", "v"} {
		for _, ns := range []string{"d", "other", ""} {
			if d := p.Authorize(Attributes{User: u, Verb: "get", Resource: "silos", Namespace: ns, Name: "a"}); d.Allowed {
				t.Errorf("%s in %q: %s", u, ns, d.Reason)
			}
		}
	}
}

func Example_matrix() {
	p := builtinPolicy(&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "e", Namespace: "d"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}})
	for _, v := range []string{v1.VerbUse, v1.VerbReadValue, v1.VerbApprove} {
		fmt.Println(v, p.Authorize(Attributes{User: "ed", Verb: v, Resource: "secrets", Namespace: "d", Name: "k", Labels: map[string]string{}}).Allowed)
	}
	// Output:
	// use true
	// read-value false
	// approve false
}
