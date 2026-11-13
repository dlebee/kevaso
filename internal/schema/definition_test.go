package schema

import (
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func def(name string, mut func(*v1.KindDefinitionSpec)) *v1.KindDefinition {
	d := &v1.KindDefinition{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "KindDefinition"}, ObjectMeta: meta.ObjectMeta{Name: name},
		Spec: v1.KindDefinitionSpec{Group: "acme.dev", Version: "v1", Scope: v1.Namespaced,
			Names:  v1.KindNames{Kind: "Database", Plural: "databases", ShortNames: []string{"db"}},
			Schema: v1.JSONSchema{Type: "object", PreserveUnknown: true}}}
	if mut != nil {
		mut(&d.Spec)
	}
	return d
}

func TestCheckDefinition(t *testing.T) {
	if errs := CheckDefinition(def("databases.acme.dev", nil), nil, nil); len(errs) > 0 {
		t.Fatalf("a good definition: %q", errs)
	}
	for _, tc := range []struct {
		name string
		d    *v1.KindDefinition
		want string
	}{
		{"name", def("databases", nil), "metadata.name must be PLURAL.GROUP: databases.acme.dev"},
		{"no domain", def("databases.acme", func(s *v1.KindDefinitionSpec) { s.Group = "acme" }), "at least one dot"},
		{"kevaso's group", def("databases.kevaso", func(s *v1.KindDefinitionSpec) { s.Group = "kevaso" }), "is Kevaso's"},
		{"kevaso.com", def("databases.x.kevaso.com", func(s *v1.KindDefinitionSpec) { s.Group = "x.kevaso.com" }), "is Kevaso's"},
		{"version", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Version = "v1beta1" }), "want v1, v2"},
		{"kind", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.Kind = "database" }), "upper-case"},
		{"scope", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Scope = "Global" }), "Namespaced or Cluster"},
		{"shadows a kind", def("silos.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.Kind, s.Names.Plural = "Silo", "silos" }), `"Silo" is the built-in kind Silo's`},
		{"shadows a plural", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.Singular = "hosts" }), "built-in kind Host's"},
		{"shadows a short name", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.ShortNames = []string{"SVC"} }), "built-in kind Service's"},
		{"shadows the definitions", def("kinddefinitions.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.Kind, s.Names.Plural = "Thing", "kinddefinitions" }), "KindDefinition's"},
		{"schema", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) { s.Schema = v1.JSONSchema{Type: "string"} }), "root's type must be object"},
		{"printer column", def("databases.acme.dev", func(s *v1.KindDefinitionSpec) {
			s.PrinterColumns = []v1.PrinterColumn{{Name: "Engine", JSONPath: "spec.engine"}}
		}), "starts with a dot"},
	} {
		errs := CheckDefinition(tc.d, nil, nil)
		if !strings.Contains(strings.Join(errs, "; "), tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, errs, tc.want)
		}
	}
	// One kind name per group; another group may have its own.
	other := def("dbs.acme.dev", func(s *v1.KindDefinitionSpec) { s.Names.Plural, s.Names.ShortNames = "dbs", nil })
	if errs := CheckDefinition(def("databases.acme.dev", nil), nil, []*v1.KindDefinition{other}); len(errs) != 1 || !strings.Contains(errs[0], "dbs.acme.dev already defines Database") {
		t.Errorf("same kind twice in a group: %q", errs)
	}
	elsewhere := def("databases.example.com", func(s *v1.KindDefinitionSpec) { s.Group = "example.com" })
	if errs := CheckDefinition(def("databases.acme.dev", nil), nil, []*v1.KindDefinition{elsewhere}); len(errs) > 0 {
		t.Errorf("same kind in another group: %q", errs)
	}
	// What can't change.
	old := def("databases.acme.dev", nil)
	changed := def("databases.acme.dev", func(s *v1.KindDefinitionSpec) {
		s.Scope, s.Version = v1.Cluster, "v2"
		s.Names.ShortNames = []string{"dbx"} // this one may change
	})
	errs := strings.Join(CheckDefinition(changed, old, nil), "; ")
	for _, w := range []string{"spec.version can't change", "spec.scope can't change"} {
		if !strings.Contains(errs, w) {
			t.Errorf("immutable fields: %q, want %q", errs, w)
		}
	}
	if strings.Contains(errs, "shortNames") {
		t.Errorf("short names may change: %q", errs)
	}
}

func TestJSONPath(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{"engine": "postgres", "n": int64(3), "list": []any{"a", "b"}, "m": map[string]any{"a.b": "dotted"}},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Synced", "status": "False"},
			map[string]any{"type": "Ready", "status": "True"},
		}}}
	for path, want := range map[string]string{
		".spec.engine":   "postgres",
		".spec.n":        "3",
		".spec.list[1]":  "b",
		".spec.list":     `["a","b"]`,
		`.spec.m["a.b"]`: "dotted",
		`.status.conditions[?(@.type=="Ready")].status`:  "True",
		`.status.conditions[?(@.type=='Synced')].status`: "False",
		`.status.conditions[?(@.type=="Gone")].status`:   "-",
		".spec.missing": "-",
		".spec.list[9]": "-",
	} {
		p, err := ParseJSONPath(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		v, ok := p.Find(obj)
		if got := Format(v, ok); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	for _, bad := range []string{"spec", ".spec..x", ".a[", ".a[?(@.x)]", ".a[x]"} {
		if _, err := ParseJSONPath(bad); err == nil {
			t.Errorf("%s: parsed", bad)
		}
	}
}
