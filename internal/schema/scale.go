package schema

import (
	"fmt"
	"regexp"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// The scale subresource (ADR 0005 §10b): a defined kind names where it keeps its replica counts.

var fieldRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// FieldPath parses a dotted path into an object (.spec.replicas) into its field names.
func FieldPath(p string) ([]string, error) {
	rest, ok := strings.CutPrefix(p, ".")
	if !ok {
		return nil, fmt.Errorf("%q: want a dotted path starting with . (.spec.replicas)", p)
	}
	segs := strings.Split(rest, ".")
	for _, s := range segs {
		if !fieldRE.MatchString(s) {
			return nil, fmt.Errorf("%q: %q isn't a field name", p, s)
		}
	}
	return segs, nil
}

// checkScale says what's wrong with a kind's scale subresource: each path must be under its part
// (.spec…, .status…) and name an integer in the schema.
func checkScale(d v1.KindDefinitionSpec) []string {
	if !d.HasScale() {
		return nil
	}
	sc := d.Subresources.Scale
	var errs []string
	check := func(field, p, top string) {
		segs, err := FieldPath(p)
		if err != nil {
			errs = append(errs, fmt.Sprintf("spec.subresources.scale.%s: %v", field, err))
			return
		}
		if len(segs) < 2 || segs[0] != top {
			errs = append(errs, fmt.Sprintf("spec.subresources.scale.%s: %q must be under .%s", field, p, top))
			return
		}
		n := d.Schema
		for _, s := range segs {
			c, ok := n.Properties[s]
			if !ok {
				errs = append(errs, fmt.Sprintf("spec.subresources.scale.%s: the schema has no %s", field, p))
				return
			}
			n = c
		}
		if n.Type != "integer" {
			errs = append(errs, fmt.Sprintf("spec.subresources.scale.%s: %s must be an integer in the schema", field, p))
		}
	}
	check("specReplicasPath", sc.SpecReplicasPath, "spec")
	if sc.StatusReplicasPath != "" {
		check("statusReplicasPath", sc.StatusReplicasPath, "status")
	}
	return errs
}

// GetInt reads an integer at a path (false if it's missing or not an integer).
func GetInt(fields map[string]any, segs []string) (int64, bool) {
	var v any = fields
	for _, s := range segs {
		m, ok := v.(map[string]any)
		if !ok {
			return 0, false
		}
		if v, ok = m[s]; !ok {
			return 0, false
		}
	}
	n, ok := v.(int64)
	return n, ok
}

// SetInt writes an integer at a path, making the objects on the way.
func SetInt(fields map[string]any, segs []string, n int64) {
	m := fields
	for _, s := range segs[:len(segs)-1] {
		next, ok := m[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[s] = next
		}
		m = next
	}
	m[segs[len(segs)-1]] = n
}
