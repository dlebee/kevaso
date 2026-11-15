package rbac

import (
	"os"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-010 (remainder): the plugin installer refuses any `*` in a plugin role, but a role written
// any other way (kvo apply by an admin, a role a plugin's service account may write) still uses the
// matcher, where `*/token` matches serviceaccounts/token: a holder mints a token for any service
// account in scope. The matcher must not let a `*/SUB` pattern reach the subresources that hand
// out power; only the exact name, or `*`, may.
//
// internal/rbac is the surface lane's: this test is skipped until that lane makes the fix (see
// plugins.md in the shared notes). Run it with KEVASO_K010=1.
func TestSubresourceWildcardsNeverReachPowerfulSubresources(t *testing.T) {
	if os.Getenv("KEVASO_K010") == "" {
		t.Skip("K-010: fix belongs to the surface lane (internal/rbac matchResource); KEVASO_K010=1 runs it")
	}
	powerful := []string{"serviceaccounts/token", "silos/exec", "silos/move", "services/expose-public",
		"ingresses/publish-public", "invites/accept", "jointokens/x", "users/x", "plugins/status"}
	for _, res := range powerful {
		sub := res[len(res)-len(lastPart(res)):]
		p := NewPolicy([]meta.Object{
			&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "wild"},
				Rules: []v1.PolicyRule{{Verbs: []string{"create", "update"}, Resources: []string{"*/" + sub}}}},
			&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "wild"},
				RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "wild"}, Subjects: []v1.Subject{{Kind: "User", Name: "mallory"}}},
		})
		for _, verb := range []string{"create", "update"} {
			if d := p.Authorize(Attributes{User: "mallory", Verb: verb, Resource: res, Namespace: "payments", Name: "x"}); d.Allowed {
				t.Errorf("*/%s allowed %s %s (%s)", sub, verb, res, d.Reason)
			}
		}
	}
	// What `*/status` is for keeps working, and the exact name still matches.
	p := NewPolicy([]meta.Object{
		&v1.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "r"},
			Rules: []v1.PolicyRule{{Verbs: []string{"update"}, Resources: []string{"*/status", "serviceaccounts/token"}}}},
		&v1.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: "r"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "r"}, Subjects: []v1.Subject{{Kind: "User", Name: "u"}}},
	})
	for _, res := range []string{"silos/status", "databases.example.com/status", "serviceaccounts/token"} {
		if d := p.Authorize(Attributes{User: "u", Verb: "update", Resource: res, Namespace: "n", Name: "x"}); !d.Allowed {
			t.Errorf("%s refused: %s", res, d.Reason)
		}
	}
}

func lastPart(res string) string {
	for i := len(res) - 1; i >= 0; i-- {
		if res[i] == '/' {
			return res[i+1:]
		}
	}
	return res
}
