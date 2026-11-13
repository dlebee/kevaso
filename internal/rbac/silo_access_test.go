package rbac

import "testing"

// A terminal (silos/ssh) and files (silos/files) go with exec: editors and admins, not viewers,
// and a role that grants only exec doesn't grant them.
func TestSiloShellAndFiles(t *testing.T) {
	p := policy()
	for _, c := range []struct {
		who    string
		groups []string
		verb   string
		res    string
		want   bool
	}{
		{"bob", nil, "create", "silos/ssh", true}, // editor
		{"bob", nil, "get", "silos/files", true},
		{"bob", nil, "create", "silos/files", true},
		{"vic", []string{"team-payments"}, "create", "silos/ssh", false}, // viewer
		{"vic", []string{"team-payments"}, "get", "silos/files", false},
		{"carol", nil, "create", "silos/ssh", false}, // exec on api only
		{"carol", nil, "get", "silos/files", false},
		{"root", []string{ClusterAdmins}, "create", "silos/files", true},
	} {
		d := p.Authorize(Attributes{User: c.who, Groups: c.groups, Verb: c.verb, Resource: c.res, Namespace: "payments", Name: "api"})
		if d.Allowed != c.want {
			t.Errorf("%s %s %s: %v (%s), want %v", c.who, c.verb, c.res, d.Allowed, d.Reason, c.want)
		}
	}
	for _, r := range BuiltinRoles() {
		if r.Name != "viewer" && r.Name != "runner" {
			continue
		}
		for _, rule := range r.Rules {
			for _, res := range rule.Resources {
				if res == "silos/ssh" || res == "silos/files" {
					t.Errorf("%s has %s", r.Name, res)
				}
			}
		}
	}
}
