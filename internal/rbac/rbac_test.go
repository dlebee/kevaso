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

// Design §8.6: separate secret verbs, rules by label and by name.
func TestSecretRules(t *testing.T) {
	p := NewPolicy(append([]meta.Object{
		&v1.Role{ObjectMeta: meta.ObjectMeta{Name: "web3-dev", Namespace: "web3"}, Rules: []v1.PolicyRule{
			{Verbs: []string{"list", "use"}, Resources: []string{"secrets"}, Selector: map[string]string{"sensitivity": "normal"}},
			{Verbs: []string{"use"}, Resources: []string{"secrets"}, ResourceNames: []string{"validator-1-key"}},
		}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "dev", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "Role", Name: "web3-dev"}, Subjects: []v1.Subject{{Kind: "User", Name: "dev"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "ed", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "editor"}, Subjects: []v1.Subject{{Kind: "User", Name: "ed"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "ada", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "admin"}, Subjects: []v1.Subject{{Kind: "User", Name: "ada"}}},
		&v1.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: "vic", Namespace: "web3"}, RoleRef: v1.RoleRef{Kind: "ClusterRole", Name: "viewer"}, Subjects: []v1.Subject{{Kind: "User", Name: "vic"}}},
	}, func() []meta.Object {
		var o []meta.Object
		for _, r := range BuiltinRoles() {
			o = append(o, r)
		}
		return o
	}()...))
	normal, critical := map[string]string{"sensitivity": "normal"}, map[string]string{"sensitivity": "critical"}
	for _, c := range []struct {
		who, verb, name string
		labels          map[string]string
		want            bool
	}{
		{"dev", "get", "infura-key", normal, true}, // list covers reading metadata
		{"dev", "list", "", nil, false},            // the whole list: only with a filter
		{"dev", "use", "infura-key", normal, true},
		{"dev", "use", "db-root", critical, false},
		{"dev", "use", "validator-1-key", critical, true}, // by name
		{"dev", "get", "validator-1-key", critical, false},
		{"dev", "read-value", "infura-key", normal, false},
		{"dev", "update", "infura-key", normal, false},
		{"ed", "create", "", nil, true}, // write covers create, update, delete
		{"ed", "delete", "db-root", critical, true},
		{"ed", "use", "db-root", critical, true},
		{"ed", "read-value", "db-root", critical, false},
		{"ada", "read-value", "db-root", critical, true},
		{"vic", "list", "", nil, true},
		{"vic", "use", "infura-key", normal, false},
		{"vic", "get", "x", nil, true},
	} {
		a := Attributes{User: c.who, Verb: c.verb, Resource: "secrets", Namespace: "web3", Name: c.name, Labels: c.labels}
		if got := p.Authorize(a).Allowed; got != c.want {
			t.Errorf("%s %s secrets/%s %v: %v, want %v", c.who, c.verb, c.name, c.labels, got, c.want)
		}
	}
	// "list" and "write" are aliases only on secrets.
	if p.Authorize(Attributes{User: "dev", Verb: "get", Resource: "silos", Namespace: "web3", Name: "x", Labels: normal}).Allowed {
		t.Error("a secrets selector rule allowed something on silos")
	}
	if !p.MaySelect(Attributes{User: "dev", Verb: "list", Resource: "secrets", Namespace: "web3"}) {
		t.Error("dev should get a filtered list")
	}
	if p.MaySelect(Attributes{User: "nobody", Verb: "list", Resource: "secrets", Namespace: "web3"}) {
		t.Error("someone with no role got a filtered list")
	}
}
