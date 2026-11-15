package rbac

import (
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-058: an invite names the user and the groups it signs in with (kevaso:cluster-admins among
// them), so creating one is for cluster-admins only, by definition, however a role reads. Of the
// built-in roles only cluster-admin is one; a ClusterRole that names create invites makes nobody
// one.
func TestK058OnlyAClusterAdminIsOne(t *testing.T) {
	inviter := &v1.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: "inviter"},
		Rules: []v1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"invites"}}}}
	crb := func(name, role, user string) *v1.ClusterRoleBinding {
		return &v1.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: name},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: role}, Subjects: []v1.Subject{{Kind: "User", Name: user}}}
	}
	rb := &v1.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: "a", Namespace: "d"},
		RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "nsadmin"}}}
	p := builtinPolicy(inviter, crb("carol", "inviter", "carol"), crb("root", "cluster-admin", "root"), rb)
	for _, c := range []struct {
		user   string
		groups []string
		want   bool
	}{
		{"ops", []string{Authenticated, ClusterAdmins}, true},
		{"root", []string{Authenticated}, true},     // bound to cluster-admin by name
		{"carol", []string{Authenticated}, false},   // holds create invites, and nothing else
		{"nsadmin", []string{Authenticated}, false}, // cluster-admin bound in one namespace only
		{"bob", []string{Authenticated}, false},
	} {
		if got := p.ClusterAdmin(c.user, c.groups); got != c.want {
			t.Errorf("%s %v: ClusterAdmin %v, want %v", c.user, c.groups, got, c.want)
		}
	}
	// RBAC alone lets carol create invites: the API server's own check is what refuses her.
	if d := p.Authorize(Attributes{User: "carol", Groups: []string{Authenticated}, Verb: "create", Resource: "invites"}); !d.Allowed {
		t.Fatalf("the role does say create invites: %v", d)
	}
}
