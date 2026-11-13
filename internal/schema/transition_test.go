package schema

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// sessions has transition rules (oldSelf): an immutable field, a count that only grows, one on a
// map's values (kept by key), and one on the whole object.
const sessions = `{
  "type": "object",
  "properties": {
    "spec": {
      "type": "object",
      "properties": {
        "template": {"type": "string", "x-kevaso-validations": [{"rule": "self == oldSelf", "message": "template can't change"}]},
        "replicas": {"type": "integer", "minimum": 0},
        "generation": {"type": "integer", "x-kevaso-validations": [{"rule": "self >= oldSelf", "message": "generation only grows"}]},
        "limits": {"type": "object", "additionalProperties": {"type": "integer", "x-kevaso-validations": [{"rule": "self <= oldSelf", "message": "limits only shrink"}]}}
      }
    },
    "status": {"type": "object", "x-kevaso-preserve-unknown": true}
  },
  "x-kevaso-validations": [{"rule": "!has(oldSelf.spec.replicas) || !has(self.spec.replicas) || self.spec.replicas - oldSelf.spec.replicas <= 3", "message": "scale up by at most 3 at a time"}]
}`

func TestTransitionRules(t *testing.T) {
	s := compileJSON(t, sessions)
	for _, tc := range []struct {
		name, old, now string
		want           string // "" for valid
	}{
		{"create: no old value, no transition rule", "", `{"spec": {"template": "a", "generation": 1}}`, ""},
		{"same template", `{"spec": {"template": "a"}}`, `{"spec": {"template": "a"}}`, ""},
		{"changed template", `{"spec": {"template": "a"}}`, `{"spec": {"template": "b"}}`, "spec.template: template can't change"},
		{"template set for the first time", `{"spec": {}}`, `{"spec": {"template": "b"}}`, ""},
		{"generation grows", `{"spec": {"generation": 2}}`, `{"spec": {"generation": 3}}`, ""},
		{"generation shrinks", `{"spec": {"generation": 2}}`, `{"spec": {"generation": 1}}`, "generation only grows"},
		{"map value by key", `{"spec": {"limits": {"cpu": 4}}}`, `{"spec": {"limits": {"cpu": 2, "mem": 9}}}`, ""},
		{"map value grows", `{"spec": {"limits": {"cpu": 4}}}`, `{"spec": {"limits": {"cpu": 5}}}`, `spec.limits["cpu"]: limits only shrink`},
		{"root: +3", `{"spec": {"replicas": 1}}`, `{"spec": {"replicas": 4}}`, ""},
		{"root: +4", `{"spec": {"replicas": 1}}`, `{"spec": {"replicas": 5}}`, "at most 3 at a time"},
	} {
		f, full := object(t, "s", tc.now)
		var oldF, oldFull map[string]any
		if tc.old != "" {
			oldF, oldFull = object(t, "s", tc.old)
		}
		got := strings.Join(s.ValidateUpdate(f, full, oldF, oldFull, All), "; ")
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTransitionRulesNotInListItems(t *testing.T) {
	var js v1.JSONSchema
	_ = json.Unmarshal([]byte(`{"type": "object", "properties": {"spec": {"type": "array", "items": {"type": "integer", "x-kevaso-validations": [{"rule": "self >= oldSelf"}]}}}}`), &js)
	if _, err := Compile(js); err == nil || !strings.Contains(err.Error(), "inside a list's items") {
		t.Errorf("oldSelf in list items: %v", err)
	}
	_ = json.Unmarshal([]byte(`{"type": "object", "properties": {"spec": {"type": "object", "x-kevaso-validations": [{"rule": "self.x == oldSelf.y.z("}]}}}`), &js)
	if _, err := Compile(js); err == nil {
		t.Error("a broken transition rule compiled")
	}
}

func TestScaleSubresourceChecks(t *testing.T) {
	withScale := func(spec, status string) func(*v1.KindDefinitionSpec) {
		return func(s *v1.KindDefinitionSpec) {
			_ = json.Unmarshal([]byte(sessions), &s.Schema)
			s.Schema.Properties["status"] = v1.JSONSchema{Type: "object", Properties: map[string]v1.JSONSchema{"replicas": {Type: "integer"}, "phase": {Type: "string"}}}
			s.Subresources = &v1.KindSubresources{Scale: &v1.ScaleSubresource{SpecReplicasPath: spec, StatusReplicasPath: status}}
		}
	}
	if errs := CheckDefinition(def("databases.acme.dev", withScale(".spec.replicas", ".status.replicas")), nil, nil); len(errs) > 0 {
		t.Fatalf("a good scale subresource: %q", errs)
	}
	for _, tc := range []struct{ name, spec, status, want string }{
		{"no dot", "spec.replicas", "", "starting with ."},
		{"not under spec", ".status.replicas", "", "must be under .spec"},
		{"status path under spec", ".spec.replicas", ".spec.replicas", "must be under .status"},
		{"missing field", ".spec.count", "", "the schema has no .spec.count"},
		{"not an integer", ".spec.template", "", "must be an integer"},
		{"status not an integer", ".spec.replicas", ".status.phase", "must be an integer"},
		{"bad segment", ".spec.re-plicas", "", "isn't a field name"},
	} {
		errs := CheckDefinition(def("databases.acme.dev", withScale(tc.spec, tc.status)), nil, nil)
		if !strings.Contains(strings.Join(errs, "; "), tc.want) {
			t.Errorf("%s: %q, want %q", tc.name, errs, tc.want)
		}
	}
	fields := map[string]any{}
	SetInt(fields, []string{"spec", "replicas"}, 3)
	if n, ok := GetInt(fields, []string{"spec", "replicas"}); !ok || n != 3 {
		t.Errorf("SetInt/GetInt: %v %v", n, ok)
	}
	if _, ok := GetInt(fields, []string{"status", "replicas"}); ok {
		t.Error("GetInt of a missing path")
	}
}
