package integration

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/operators"
)

// K-010 (remainder): the installer refuses `*/token` in a package's roles, but a role bound to the
// plugin's service account from outside the package (an admin's kvo apply) used to go unseen. The
// install now checks those bindings by the same rules and refuses, naming the binding.
func TestPluginInstallRefusesOutsideRolesItWouldRefuseInThePackage(t *testing.T) {
	c := newCluster(t)
	ctx := c.ctx
	pkg, err := operators.Load("../../examples/operator-session")
	if err != nil {
		t.Fatal(err)
	}
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	if err := c.admin.Create(ctx, &v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "wild-tokens"},
		Rules: []v1.PolicyRule{{Verbs: []string{"create"}, Resources: []string{"*/token"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(ctx, &v1.ClusterRoleBinding{TypeMeta: tm("ClusterRoleBinding"), ObjectMeta: meta.ObjectMeta{Name: "sessions-extra"},
		RoleRef:  v1.RoleRef{Kind: "ClusterRole", Name: "wild-tokens"},
		Subjects: []v1.Subject{{Kind: "ServiceAccount", Name: pkg.ServiceAccount(), Namespace: v1.PluginNamespace}}}); err != nil {
		t.Fatal(err)
	}
	host := &fakeHost{t: t}
	confirmed := false
	in := &operators.Installer{API: c.admin, Server: c.url, CA: c.ca, Confirm: func(string) bool { confirmed = true; return true }}
	err = in.Install(ctx, pkg, host, operators.InstallOptions{})
	if err == nil || !strings.Contains(err.Error(), "ClusterRoleBinding sessions-extra (not from the package)") || !strings.Contains(err.Error(), "*/token") {
		t.Fatalf("install with an outside */token binding: %v", err)
	}
	if confirmed || host.creds != nil {
		t.Error("asked or started anyway")
	}
	// Without the binding it installs.
	if err := c.admin.Delete(ctx, "ClusterRoleBinding", "", "sessions-extra"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Stop(ctx, "sessions") })
	if err := in.Install(ctx, pkg, host, operators.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
}
