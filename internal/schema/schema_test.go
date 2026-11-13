package schema

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// databases is design §4.2's example, with bounds, a pattern, a default and a map.
const databases = `{
  "type": "object",
  "properties": {
    "spec": {
      "type": "object",
      "properties": {
        "engine":   {"type": "string", "enum": ["postgres", "mysql"]},
        "size":     {"type": "string", "pattern": "^[0-9]+Gi$"},
        "replicas": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1},
        "ratio":    {"type": "number", "minimum": 0, "maximum": 1, "exclusiveMaximum": true},
        "tags":     {"type": "array", "items": {"type": "string", "minLength": 1}, "maxItems": 2},
        "params":   {"type": "object", "additionalProperties": {"type": "string"}},
        "extra":    {"type": "object", "x-kevaso-preserve-unknown": true},
        "backup":   {"type": "object", "properties": {"enabled": {"type": "boolean", "default": true}, "every": {"type": "string"}}}
      },
      "required": ["engine"],
      "x-kevaso-validations": [{"rule": "self.engine != 'mysql' || has(self.size)", "message": "mysql needs a size"}]
    },
    "status": {"type": "object", "x-kevaso-preserve-unknown": true}
  },
  "x-kevaso-validations": [{"rule": "self.metadata.name.size() <= 20", "message": "names are at most 20 characters"}]
}`

func compileJSON(t *testing.T, s string) *Schema {
	t.Helper()
	var js v1.JSONSchema
	if err := json.Unmarshal([]byte(s), &js); err != nil {
		t.Fatal(err)
	}
	c, err := Compile(js)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func object(t *testing.T, name, fields string) (map[string]any, map[string]any) {
	t.Helper()
	v, err := v1.DecodeValue([]byte(fields))
	if err != nil {
		t.Fatal(err)
	}
	f := v.(map[string]any)
	full := map[string]any{"apiVersion": "acme.dev/v1", "kind": "Database", "metadata": map[string]any{"name": name}}
	for k, x := range f {
		full[k] = x
	}
	return f, full
}

func TestValidate(t *testing.T) {
	s := compileJSON(t, databases)
	for _, tc := range []struct {
		name, fields string
		part         Part
		want         []string // substrings of the problems, in order; none: valid
	}{
		{"minimal", `{"spec": {"engine": "postgres"}}`, All, nil},
		{"everything", `{"spec": {"engine": "mysql", "size": "10Gi", "replicas": 3, "ratio": 0.5, "tags": ["a"], "params": {"x": "y"}, "extra": {"any": [1, {"thing": true}]}}, "status": {"whatever": 1}}`, All, nil},
		{"required", `{"spec": {}}`, All, []string{"spec.engine: required"}},
		{"enum", `{"spec": {"engine": "oracle"}}`, All, []string{"spec.engine: must be one of postgres, mysql"}},
		{"unknown field", `{"spec": {"engine": "postgres", "colour": "blue"}}`, All, []string{"spec.colour: unknown field"}},
		{"unknown top-level field", `{"spec": {"engine": "postgres"}, "extras": 1}`, All, []string{"extras: unknown field"}},
		{"wrong type", `{"spec": {"engine": 3}}`, All, []string{"spec.engine: want a string, got a number"}},
		{"integer", `{"spec": {"engine": "postgres", "replicas": 1.5}}`, All, []string{"spec.replicas: want an integer"}},
		{"minimum", `{"spec": {"engine": "postgres", "replicas": 0}}`, All, []string{"below the minimum 1"}},
		{"maximum", `{"spec": {"engine": "postgres", "replicas": 6}}`, All, []string{"above the maximum 5"}},
		{"exclusive maximum", `{"spec": {"engine": "postgres", "ratio": 1}}`, All, []string{"above the maximum 1 (exclusive)"}},
		{"pattern", `{"spec": {"engine": "mysql", "size": "ten"}}`, All, []string{`spec.size: "ten" doesn't match`}},
		{"items", `{"spec": {"engine": "postgres", "tags": ["", "b", "c"]}}`, All, []string{"spec.tags: at most 2 items", "spec.tags[0]: at least 1 characters"}},
		{"map values", `{"spec": {"engine": "postgres", "params": {"x": 1}}}`, All, []string{`spec.params["x"]: want a string`}},
		{"null", `{"spec": {"engine": null}}`, All, []string{"spec.engine: null isn't allowed"}},
		{"node rule", `{"spec": {"engine": "mysql"}}`, All, []string{"spec: mysql needs a size"}},
		{"root rule", `{"spec": {"engine": "postgres"}}`, All, nil},
		{"main part skips status", `{"spec": {"engine": "postgres"}, "status": 5}`, Main, nil},
		{"status part skips spec", `{"spec": {"engine": "nope"}, "status": {"ok": true}}`, Status, nil},
		{"status part checks status", `{"status": 5}`, Status, []string{"status: want an object"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, full := object(t, "db1", tc.fields)
			got := s.Validate(f, full, tc.part)
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d: %q, want it to say %q", i, got[i], w)
				}
			}
		})
	}
	f, full := object(t, "a-very-long-database-name", `{"spec": {"engine": "postgres"}}`)
	if got := s.Validate(f, full, All); len(got) != 1 || got[0] != "names are at most 20 characters" {
		t.Errorf("root rule: %q", got)
	}
}

func TestDefaults(t *testing.T) {
	s := compileJSON(t, databases)
	f, _ := object(t, "db", `{"spec": {"engine": "postgres", "backup": {}}}`)
	s.Default(f, All)
	b, _ := json.Marshal(f)
	if want := `{"spec":{"backup":{"enabled":true},"engine":"postgres","replicas":1}}`; string(b) != want {
		t.Errorf("defaults: %s, want %s", b, want)
	}
	// No object is made just to hold a default, and Status leaves spec alone.
	f, _ = object(t, "db", `{"spec": {"engine": "postgres"}}`)
	s.Default(f, Status)
	if _, ok := f["spec"].(map[string]any)["replicas"]; ok {
		t.Error("Status part defaulted spec")
	}
}

func TestCompileRefuses(t *testing.T) {
	for _, tc := range []struct{ schema, want string }{
		{`{"type": "array", "items": {"type": "string"}}`, "root's type must be object"},
		{`{"type": "object", "properties": {"metadata": {"type": "object"}}}`, "metadata isn't the schema's"},
		{`{"type": "object", "properties": {"spec": {"properties": {}}}}`, "schema spec: needs a type"},
		{`{"type": "object", "properties": {"spec": {"type": "map"}}}`, `type "map"`},
		{`{"type": "object", "properties": {"n": {"type": "string", "minimum": 1}}}`, "minimum and maximum are for numbers"},
		{`{"type": "object", "properties": {"n": {"type": "string", "pattern": "("}}}`, "pattern"},
		{`{"type": "object", "properties": {"l": {"type": "array"}}}`, "an array needs items"},
		{`{"type": "object", "required": ["x"], "properties": {"y": {"type": "string"}}}`, `required "x"`},
		{`{"type": "object", "properties": {"n": {"type": "integer", "default": "one"}}}`, "default: n: want an integer"},
		{`{"type": "object", "properties": {"n": {"type": "string", "enum": ["a", 2]}}}`, "enum[1]"},
		{`{"type": "object", "x-kevaso-validations": [{"rule": "self.spec ==", "message": "x"}]}`, "x-kevaso-validations[0]"},
		{`{"type": "object", "properties": {"m": {"type": "object", "additionalProperties": {"type": "string"}, "properties": {"a": {"type": "string"}}}}}`, "additionalProperties"},
	} {
		var js v1.JSONSchema
		if err := json.Unmarshal([]byte(tc.schema), &js); err != nil {
			t.Fatal(err)
		}
		if _, err := Compile(js); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error saying %q", tc.schema, err, tc.want)
		}
	}
}

func TestRuleCostIsBounded(t *testing.T) {
	s := compileJSON(t, `{"type": "object", "properties": {"spec": {"type": "object", "properties": {"l": {"type": "array", "items": {"type": "integer"}}},
		"x-kevaso-validations": [{"rule": "self.l.all(a, self.l.all(b, self.l.all(c, a + b + c >= 0)))", "message": "slow"}]}}}`)
	l := make([]any, 300)
	for i := range l {
		l[i] = int64(i)
	}
	f := map[string]any{"spec": map[string]any{"l": l}}
	got := s.Validate(f, f, All)
	if len(got) != 1 || !strings.Contains(got[0], "cost") {
		t.Errorf("an expensive rule: %q, want it refused for its cost", got)
	}
}
