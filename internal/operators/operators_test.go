package operators

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func tm(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }

func goodPackage() *Package {
	kd := &v1.KindDefinition{TypeMeta: tm("KindDefinition"), ObjectMeta: meta.ObjectMeta{Name: "sessions.example.dev"},
		Spec: v1.KindDefinitionSpec{Group: "example.dev", Version: "v1", Names: v1.KindNames{Kind: "Session", Plural: "sessions"}, Scope: v1.Namespaced}}
	return &Package{
		Manifest: Manifest{APIVersion: v1.APIVersion, Kind: "PluginPackage", Metadata: ManifestMeta{Name: "sessions"},
			Spec: ManifestSpec{Version: "0.1.0", Controller: ManifestController{Binary: "bin/x"}}},
		Kinds: []*v1.KindDefinition{kd},
		VPols: []*v1.ValidationPolicy{{TypeMeta: tm("ValidationPolicy"), ObjectMeta: meta.ObjectMeta{Name: "sessions-p"},
			Spec: v1.ValidationPolicySpec{Match: v1.PolicyMatch{Kinds: []string{"sessions.example.dev"}}}}},
		CRoles: []*v1.ClusterRole{{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "sessions-controller"},
			Rules: []v1.PolicyRule{{Verbs: []string{"get", "list", "watch"}, Resources: []string{"sessions.example.dev", "silos"}}}}},
	}
}

func TestCheckPackage(t *testing.T) {
	if errs := Check(goodPackage()); len(errs) > 0 {
		t.Fatalf("a good package: %q", errs)
	}
	for _, tc := range []struct {
		name string
		mut  func(p *Package)
		want string
	}{
		{"kind", func(p *Package) { p.Manifest.Kind = "Plugin" }, "kind PluginPackage"},
		{"name", func(p *Package) { p.Manifest.Metadata.Name = "Sessions" }, "metadata.name"},
		{"version", func(p *Package) { p.Manifest.Spec.Version = "latest" }, "semantic version"},
		{"no binary", func(p *Package) { p.Manifest.Spec.Controller.Binary = "" }, "spec.controller.binary"},
		{"policy on a built-in", func(p *Package) { p.VPols[0].Spec.Match.Kinds = []string{"Silo"} }, `match.kinds "Silo": a plugin's policies apply only to the kinds it defines`},
		{"policy on everything", func(p *Package) { p.VPols[0].Spec.Match.Kinds = []string{"*"} }, `match.kinds "*"`},
		{"policy name", func(p *Package) { p.VPols[0].Name = "mine" }, "name it sessions-…"},
		{"wildcard verb", func(p *Package) { p.CRoles[0].Rules[0].Verbs = []string{"*"} }, "verbs: * isn't for plugins"},
		{"wildcard resource", func(p *Package) { p.CRoles[0].Rules[0].Resources = []string{"*"} }, "resources: * isn't for plugins"},
		{"cluster-admin by RBAC", func(p *Package) { p.CRoles[0].Rules[0].Resources = []string{"clusterrolebindings"} }, "never gets it"},
		{"tokens", func(p *Package) { p.CRoles[0].Rules[0].Resources = []string{"serviceaccounts/token"} }, "never gets it"},
		{"definitions", func(p *Package) { p.CRoles[0].Rules[0].Resources = []string{"kinddefinitions"} }, "never gets it"},
		{"secret values", func(p *Package) {
			p.CRoles[0].Rules[0] = v1.PolicyRule{Verbs: []string{"read-value"}, Resources: []string{"secrets"}}
		}, "read-value on secrets is for people"},
		{"empty role", func(p *Package) { p.CRoles[0].Rules = nil }, "no rules"},
		{"role without namespace", func(p *Package) {
			p.Roles = []*v1.Role{{TypeMeta: tm("Role"), ObjectMeta: meta.ObjectMeta{Name: "sessions-r"}, Rules: p.CRoles[0].Rules}}
		}, "needs metadata.namespace"},
		{"twice", func(p *Package) { p.Kinds = append(p.Kinds, p.Kinds[0]) }, "twice in the package"},
	} {
		p := goodPackage()
		tc.mut(p)
		if got := strings.Join(Check(p), "; "); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestLoadExamplePackage(t *testing.T) {
	p, err := Load("../../examples/operator-session")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "sessions" || len(p.Kinds) != 2 || len(p.VPols) != 1 || len(p.CRoles) != 1 || p.ServiceAccount() != "plugin-sessions" {
		t.Errorf("loaded %+v", p.Manifest)
	}
	if _, err := Load("."); err == nil {
		t.Error("a directory without plugin.yaml")
	}
}

func owned(by string) meta.Object {
	o := &v1.ClusterRole{TypeMeta: tm("ClusterRole"), ObjectMeta: meta.ObjectMeta{Name: "r"}}
	if by != "" {
		o.OwnerReferences = []meta.OwnerReference{{APIVersion: v1.APIVersion, Kind: "Plugin", Name: by}}
	}
	return o
}

func TestDecideOwnership(t *testing.T) {
	want := owned("")
	for _, tc := range []struct {
		name   string
		stored meta.Object
		adopt  bool
		want   Decision
		err    string
	}{
		{"new", nil, false, Create, ""},
		{"ours: an upgrade", owned("sessions"), false, Update, ""},
		{"another plugin's", owned("tasks"), false, "", "belongs to plugin tasks"},
		{"another plugin's, even adopting", owned("tasks"), true, "", "belongs to plugin tasks"},
		{"nobody's", owned(""), false, "", "--adopt takes it over"},
		{"nobody's, adopted", owned(""), true, Update, ""},
	} {
		d, errs := Decide("sessions", []meta.Object{want}, []meta.Object{tc.stored}, tc.adopt)
		got := strings.Join(errs, "; ")
		if tc.err == "" && (got != "" || d[0] != tc.want) || tc.err != "" && !strings.Contains(got, tc.err) {
			t.Errorf("%s: %v %q", tc.name, d, got)
		}
	}
}

func TestCheckUninstallAndLeftovers(t *testing.T) {
	for _, tc := range []struct {
		left  map[string]int
		force bool
		err   string
	}{
		{map[string]int{"sessions.example.dev": 0}, false, ""},
		{map[string]int{"sessions.example.dev": 2, "sessiontemplates.example.dev": 1}, false, "2 sessions.example.dev, 1 sessiontemplates.example.dev"},
		{map[string]int{"sessions.example.dev": 2}, true, ""},
		{nil, false, ""},
	} {
		err := CheckUninstall("sessions", tc.left, tc.force)
		if (tc.err == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%v force=%v: %v", tc.left, tc.force, err)
		}
	}
	a, b := v1.PluginObject{Kind: "KindDefinition", Name: "a"}, v1.PluginObject{Kind: "ClusterRole", Name: "b"}
	if got := Leftovers([]v1.PluginObject{a, b}, []v1.PluginObject{b}); len(got) != 1 || got[0] != a {
		t.Errorf("leftovers: %v", got)
	}
}

// What every controller gets on top of its package's roles is exactly its own heartbeat and its
// own token, by name.
func TestSelfRolesAreNarrow(t *testing.T) {
	for _, o := range selfObjects("sessions") {
		var rules []v1.PolicyRule
		switch r := o.(type) {
		case *v1.ClusterRole:
			rules = r.Rules
		case *v1.Role:
			rules = r.Rules
		}
		for _, r := range rules {
			if len(r.ResourceNames) != 1 || len(r.Verbs) != 1 {
				t.Errorf("%s: %+v", o.GetObjectMeta().Name, r)
			}
		}
	}
	if s := Summary(goodPackage(), "cp1"); !strings.Contains(s, "plugins/status (only sessions)") || !strings.Contains(s, "on cp1 as kevaso-system/plugin-sessions") {
		t.Errorf("summary:\n%s", s)
	}
}
