package rbac

import (
	"slices"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The role matrix lists its resources by hand, and a kind added to the API (mutationpolicies was
// one; K-003 passed through that gap) is not in it. This test takes the resources from the API's
// own list of kinds instead: whatever the matrix does not say a built-in role may do with a kind,
// the role may not do, for every verb, in its own namespace, in another one, and cluster-wide;
// and cluster-admin may do everything with every kind.
func TestEveryKindOfTheAPIIsDeniedToABuiltinRoleUnlessTheMatrixGrantsIt(t *testing.T) {
	want := expected()
	var bindings []meta.Object
	for role := range want {
		bindings = append(bindings, &v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role, Namespace: "d"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: role + "-user"}}})
	}
	p := builtinPolicy(bindings...)
	kinds := v1.Kinds()
	if len(kinds) < 20 {
		t.Fatalf("only %d kinds: the registry is not what this test thinks", len(kinds))
	}
	for _, k := range kinds {
		for role, g := range want {
			for _, verb := range allVerbs {
				for _, ns := range []string{"d", "other", ""} {
					a := Attributes{User: role + "-user", Groups: []string{Authenticated}, Verb: verb, Resource: k.Plural, Namespace: ns, Name: "x", Labels: map[string]string{}}
					got := p.Authorize(a).Allowed
					wantAllowed := ns == "d" && k.Scope == v1.Namespaced && slices.Contains(g[k.Plural], verb)
					if got != wantAllowed {
						t.Errorf("%s: %s %s (%s kind) in %q: allowed %v, want %v", role, verb, k.Plural, k.Scope, ns, got, wantAllowed)
					}
				}
			}
		}
		for _, verb := range allVerbs {
			for _, ns := range []string{"d", ""} {
				if !p.Authorize(Attributes{User: "root", Groups: []string{ClusterAdmins}, Verb: verb, Resource: k.Plural, Namespace: ns}).Allowed {
					t.Errorf("cluster-admin: %s %s in %q refused", verb, k.Plural, ns)
				}
			}
		}
	}
}
