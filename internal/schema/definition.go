package schema

import (
	"fmt"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// CheckDefinition says everything wrong with a KindDefinition (ADR 0005): its names, its group,
// its schema, and, on an update (old != nil), the fields that can't change. others are the other
// stored definitions.
func CheckDefinition(d, old *v1.KindDefinition, others []*v1.KindDefinition) []string {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	s := d.Spec
	if err := v1.ValidateGroup(s.Group); err != nil {
		add("spec.group: %v", err)
	}
	if err := v1.ValidateVersion(s.Version); err != nil {
		add("spec.version: %v", err)
	}
	if err := v1.ValidateKindName(s.Names.Kind); err != nil {
		add("spec.names.kind: %v", err)
	}
	if err := meta.ValidateName(s.Names.Plural); err != nil {
		add("spec.names.plural: %v", err)
	}
	if want := s.Resource(); d.Name != want {
		add("metadata.name must be PLURAL.GROUP: %s", want)
	}
	if s.Names.Singular != "" {
		if err := meta.ValidateName(s.Names.Singular); err != nil {
			add("spec.names.singular: %v", err)
		}
	}
	for _, n := range s.Names.ShortNames {
		if err := meta.ValidateName(n); err != nil {
			add("spec.names.shortNames: %v", err)
		}
	}
	if s.Scope != v1.Namespaced && s.Scope != v1.Cluster {
		add("spec.scope: Namespaced or Cluster")
	}
	names := append([]string{s.Names.Kind, s.Names.Plural, s.Names.Singular}, s.Names.ShortNames...)
	for _, n := range names {
		if n == "" {
			continue
		}
		if k, ok := v1.ShadowsBuiltin(n); ok {
			add("spec.names: %q is the built-in kind %s's: a defined kind can't shadow a built-in one", n, k.Kind)
		}
	}
	for _, o := range others {
		if o.Name != d.Name && o.Spec.Group == s.Group && strings.EqualFold(o.Spec.Names.Kind, s.Names.Kind) {
			add("spec.names.kind: %s already defines %s in %s", o.Name, o.Spec.Names.Kind, s.Group)
		}
	}
	if _, err := Compile(s.Schema); err != nil {
		add("spec.%v", err)
	}
	for i, c := range s.PrinterColumns {
		if c.Name == "" {
			add("spec.printerColumns[%d]: needs a name", i)
		}
		if _, err := ParseJSONPath(c.JSONPath); err != nil {
			add("spec.printerColumns[%d].jsonPath: %v", i, err)
		}
	}
	if old != nil {
		o := old.Spec
		for _, f := range []struct {
			name     string
			was, now string
		}{{"group", o.Group, s.Group}, {"version", o.Version, s.Version}, {"names.kind", o.Names.Kind, s.Names.Kind},
			{"names.plural", o.Names.Plural, s.Names.Plural}, {"scope", string(o.Scope), string(s.Scope)}} {
			if f.was != f.now {
				add("spec.%s can't change (%q → %q): every stored object and role uses it", f.name, f.was, f.now)
			}
		}
	}
	return errs
}
