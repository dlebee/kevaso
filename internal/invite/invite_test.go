package invite

import (
	"strings"
	"testing"
)

// The role an invite gives is always explicit about its kind and where it applies.
func TestPlanSaysWhichRoleAndWhere(t *testing.T) {
	for _, c := range []struct {
		r    Request
		want *Binding
	}{
		{Request{User: "bob"}, nil}, // no role: the invite only
		{Request{User: "bob", Namespace: "payments"}, nil},
		{Request{User: "bob", Namespace: "payments", Role: "role/deployer"},
			&Binding{Kind: "RoleBinding", Name: "bob-role-deployer", Namespace: "payments", RoleKind: "Role", RoleName: "deployer"}},
		{Request{User: "bob", Namespace: "payments", Role: "clusterrole/editor"},
			&Binding{Kind: "RoleBinding", Name: "bob-clusterrole-editor", Namespace: "payments", RoleKind: "ClusterRole", RoleName: "editor"}},
		{Request{User: "bob", ClusterRole: "viewer"},
			&Binding{Kind: "ClusterRoleBinding", Name: "bob-clusterrole-viewer", RoleKind: "ClusterRole", RoleName: "viewer"}},
	} {
		got, err := c.r.Plan()
		if err != nil {
			t.Fatalf("%+v: %v", c.r, err)
		}
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%+v: %+v, want %+v", c.r, got, c.want)
		}
	}
}

// A Role and a ClusterRole of the same name never share a binding.
func TestBindingNamesDontCollide(t *testing.T) {
	a, _ := Request{User: "bob", Namespace: "payments", Role: "role/editor"}.Plan()
	b, _ := Request{User: "bob", Namespace: "payments", Role: "clusterrole/editor"}.Plan()
	if a.Name == b.Name {
		t.Fatalf("both are %s", a.Name)
	}
}

func TestPlanRefusals(t *testing.T) {
	for _, c := range []struct {
		r    Request
		says string
	}{
		{Request{}, "needs NAME"},
		{Request{User: "bob", Namespace: "payments", Role: "editor"}, "say which kind of role"}, // a bare name
		{Request{User: "bob", Namespace: "payments", Role: "editor"}, "--cluster-role NAME"},    // names the three forms
		{Request{User: "bob", Namespace: "payments", Role: "group/editor"}, "isn't a kind of role"},
		{Request{User: "bob", Namespace: "payments", Role: "role/"}, "say which kind of role"},
		{Request{User: "bob", Role: "clusterrole/editor"}, "needs -n NS"},
		{Request{User: "bob", Role: "role/deployer"}, "needs -n NS"},
		{Request{User: "bob", Namespace: "payments", ClusterRole: "viewer"}, "takes no -n"},
		{Request{User: "bob", Namespace: "payments", ClusterRole: "viewer"}, "--role clusterrole/viewer"}, // and says what to use
		{Request{User: "bob", ClusterRole: "clusterrole/viewer"}, "no prefix"},
		{Request{User: "bob", Namespace: "payments", Role: "role/a", ClusterRole: "b"}, "one role per invite"},
	} {
		_, err := c.r.Plan()
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%+v: %v, want it to say %q", c.r, err, c.says)
		}
	}
}

func TestDescribe(t *testing.T) {
	for _, c := range []struct {
		r    Request
		want string
	}{
		{Request{User: "bob", Namespace: "payments", Role: "role/deployer"}, "the Role deployer in namespace payments"},
		{Request{User: "bob", Namespace: "payments", Role: "clusterrole/editor"}, "the ClusterRole editor in namespace payments"},
		{Request{User: "bob", ClusterRole: "viewer"}, "the ClusterRole viewer in every namespace"},
	} {
		r, want := c.r, c.want
		b, err := r.Plan()
		if err != nil || b.Describe() != want {
			t.Errorf("%+v: %q %v", r, b.Describe(), err)
		}
	}
}
