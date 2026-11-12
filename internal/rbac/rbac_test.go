package rbac

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func policy() *Policy {
	var objs []meta.Object
	for _, r := range BuiltinRoles() {
		objs = append(objs, r)
	}
	for _, b := range BuiltinBindings() {
		objs = append(objs, b)
	}
	objs = append(objs,
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "bob-edits", Namespace: "payments"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "bob"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "team-views", Namespace: "payments"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}, Subjects: []v1.Subject{{Kind: "Group", Name: "team-payments"}}},
		&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "exec-api", Namespace: "payments"},
			Rules: []v1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"silos/exec"}, ResourceNames: []string{"api"}}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "carol-exec-api", Namespace: "payments"},
			RoleRef: v1.RoleRef{Kind: "Role", Name: "exec-api"}, Subjects: []v1.Subject{{Kind: "User", Name: "carol"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "ci", Namespace: "payments"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: "deployer"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "dangling", Namespace: "payments"},
			RoleRef: v1.RoleRef{Kind: "Role", Name: "does-not-exist"}, Subjects: []v1.Subject{{Kind: "User", Name: "dave"}}},
		// A RoleBinding to cluster-admin is still only for its namespace.
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "erin-admin", Namespace: "lab"},
			RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "erin"}}},
	)
	return NewPolicy(objs)
}

func TestAuthorize(t *testing.T) {
	p := policy()
	admin := []string{ClusterAdmins, Authenticated}
	for _, c := range []struct {
		who    string
		groups []string
		verb   string
		res    string
		ns     string
		name   string
		want   bool
	}{
		{"root", admin, "delete", "hosts", "", "hv1", true},
		{"root", admin, "create", "silos/exec", "payments", "api", true},
		{"bob", nil, "create", "silos", "payments", "", true},
		{"bob", nil, "create", "silos/exec", "payments", "api", true},
		{"bob", nil, "list", "silos", "other", "", false},             // only his namespace
		{"bob", nil, "list", "silos", "", "", false},                  // not cluster-wide
		{"bob", nil, "create", "rolebindings", "payments", "", false}, // editor isn't admin
		{"bob", nil, "update", "silos/status", "payments", "web", false},
		{"bob", nil, "list", "hosts", "", "", false},
		{"bob", nil, "get", "namespaces", "", "payments", true}, // he has a role there
		{"bob", nil, "get", "namespaces", "", "other", false},
		{"bob", nil, "delete", "namespaces", "", "payments", false},
		{"vic", []string{"team-payments"}, "get", "silos", "payments", "api", true},
		{"vic", []string{"team-payments"}, "delete", "silos", "payments", "api", false},
		{"vic", []string{"team-payments"}, "create", "silos/exec", "payments", "api", false},
		{"carol", nil, "create", "silos/exec", "payments", "api", true},
		{"carol", nil, "create", "silos/exec", "payments", "db", false}, // resourceNames
		{"carol", nil, "get", "silos", "payments", "api", false},
		{ServiceAccountUser("payments", "deployer"), nil, "update", "silos", "payments", "api", true},
		{ServiceAccountUser("other", "deployer"), nil, "update", "silos", "payments", "api", false},
		{"dave", nil, "get", "silos", "payments", "api", false}, // binding to a missing role
		{"erin", nil, "delete", "silos", "lab", "x", true},
		{"erin", nil, "delete", "silos", "payments", "x", false},
		{"erin", nil, "list", "hosts", "", "", false}, // cluster-admin via RoleBinding: no cluster scope
		{"mallory", []string{Authenticated}, "get", "silos", "payments", "api", false},
	} {
		d := p.Authorize(Attributes{User: c.who, Groups: c.groups, Verb: c.verb, Resource: c.res, Namespace: c.ns, Name: c.name})
		if d.Allowed != c.want {
			t.Errorf("%s %s %s ns=%q name=%q: allowed=%v (%s), want %v", c.who, c.verb, c.res, c.ns, c.name, d.Allowed, d.Reason, c.want)
		}
		if d.Reason == "" {
			t.Errorf("%s %s %s: no reason", c.who, c.verb, c.res)
		}
	}
}

func TestReasons(t *testing.T) {
	p := policy()
	d := p.Authorize(Attributes{User: "bob", Verb: "create", Resource: "silos", Namespace: "payments"})
	if d.Reason != "RoleBinding payments/bob-edits (ClusterRole editor)" {
		t.Errorf("allow reason %q", d.Reason)
	}
	d = p.Authorize(Attributes{User: "bob", Verb: "list", Resource: "silos", Namespace: "other"})
	if !strings.Contains(d.Reason, "no role lets bob list silos in namespace other") {
		t.Errorf("deny reason %q", d.Reason)
	}
}

func TestNamespacesFor(t *testing.T) {
	p := policy()
	if got := p.NamespacesFor(Attributes{User: "bob"}); strings.Join(got, ",") != "payments" {
		t.Errorf("bob: %v", got)
	}
	if got := p.NamespacesFor(Attributes{User: "erin"}); strings.Join(got, ",") != "lab" {
		t.Errorf("erin: %v", got)
	}
	if got := p.NamespacesFor(Attributes{User: "mallory"}); len(got) != 0 {
		t.Errorf("mallory: %v", got)
	}
}

func TestStatusWildcard(t *testing.T) {
	rules := []v1.PolicyRule{{Verbs: []string{"update"}, Resources: []string{"*/status"}}}
	if !allows(rules, Attributes{Verb: "update", Resource: "silos/status"}) || allows(rules, Attributes{Verb: "update", Resource: "silos"}) {
		t.Fatal("*/status")
	}
}
