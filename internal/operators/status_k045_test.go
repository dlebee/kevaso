package operators

import (
	"context"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-045: a package's role could hold update on silos/status, hosts/status, ips/status or
// services/status (only plugins/status was refused): with silos/status its controller reaches a
// silo's host, its volumes' devices and its firewall ranges, and the operator saw one ordinary rule
// line. Now an install whose roles write a built-in kind's status is refused unless the operator
// names exactly those (InstallOptions.StatusWrites), before anything is asked or applied; when
// named, they are shown on a line of their own before the yes.
func TestBuiltinStatusWritesNeedTheOperatorsWord(t *testing.T) {
	p := goodPackage()
	p.CRoles[0].Rules = append(p.CRoles[0].Rules,
		v1.PolicyRule{Verbs: []string{"get", "list", "watch"}, Resources: []string{"hosts/status"}}, // reading is not writing
		v1.PolicyRule{Verbs: []string{"update"}, Resources: []string{"silos/status", "sessions.example.dev/status"}})
	p.Roles = []*v1.Role{{TypeMeta: tm("Role"), ObjectMeta: p.CRoles[0].ObjectMeta, Rules: []v1.PolicyRule{{Verbs: []string{"patch"}, Resources: []string{"ips/status"}}}}}
	p.Roles[0].Name, p.Roles[0].Namespace = "sessions-ips", "shop"
	if errs := Check(p); len(errs) > 0 {
		t.Fatalf("the package itself is fine: %q", errs)
	}
	if got := BuiltinStatusWrites(p); strings.Join(got, ",") != "ips/status,silos/status" {
		t.Fatalf("built-in status writes: %v", got)
	}

	asked := false
	in := &Installer{Confirm: func(string) bool { asked = true; return true }}
	err := in.Install(context.Background(), p, nil, InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "ips/status, silos/status") || !strings.Contains(err.Error(), "--allow-status ips/status,silos/status") || asked {
		t.Fatalf("not named: %v (asked: %v)", err, asked)
	}
	err = in.Install(context.Background(), p, nil, InstallOptions{StatusWrites: []string{"silos/status"}})
	if err == nil || !strings.Contains(err.Error(), "ips/status") || asked {
		t.Fatalf("one of two named: %v (asked: %v)", err, asked)
	}
	err = in.Install(context.Background(), p, nil, InstallOptions{StatusWrites: []string{"ips/status", "silos/status", "hosts/status"}})
	if err == nil || !strings.Contains(err.Error(), "hosts/status") || asked {
		t.Fatalf("named more than it writes: %v (asked: %v)", err, asked)
	}
	if err := StatusWriteProblem(p, []string{"silos/status", "ips/status"}); err != nil {
		t.Fatalf("named exactly: %v", err)
	}
	s := StatusGrants(BuiltinStatusWrites(p))
	if !strings.Contains(s, "status of built-in objects") || !strings.Contains(s, "ips/status, silos/status") {
		t.Fatalf("what the operator is shown: %q", s)
	}
	if StatusGrants(nil) != "" {
		t.Fatal("a package writing no built-in status is shown a grant line")
	}
}
