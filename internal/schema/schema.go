// Package schema checks objects of defined kinds against their KindDefinition's schema (ADR 0005):
// an OpenAPI v3 subset (types, properties, required, enum, bounds, patterns, no unknown fields
// unless the schema says so), defaults, and CEL rules on any node.
//
// Values are plain JSON as v1.DecodeValue makes them: map[string]any, []any, string, bool, int64,
// float64, nil.
package schema

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"

	v1 "kevaso.com/core/api/v1"
)

// CostLimit bounds what one CEL rule may cost, so a rule over a big list can't stall the server.
const CostLimit = 1_000_000

// Schema is a compiled schema.
type Schema struct{ root *node }

type node struct {
	s       v1.JSONSchema
	props   map[string]*node
	items   *node
	addl    *node
	pattern *regexp.Regexp
	rules   []rule
}

type rule struct {
	v1.ValidationRule
	prg        cel.Program
	transition bool // uses oldSelf: checked only on updates, against the node's old value
}

var types = []string{"object", "array", "string", "integer", "number", "boolean"}

// Env is the CEL environment of schema rules: `self` is the node the rule is on.
func Env() (*cel.Env, error) { return cel.NewEnv(cel.Variable("self", cel.DynType)) }

// TransitionEnv adds `oldSelf`, the node's value before an update: a rule that uses it is a
// transition rule (ADR 0005 §8a).
func TransitionEnv() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("self", cel.DynType), cel.Variable("oldSelf", cel.DynType))
}

type envs struct{ plain, transition *cel.Env }

// Compile checks a schema and compiles its rules. The root must be an object.
func Compile(s v1.JSONSchema) (*Schema, error) {
	if s.Type != "object" {
		return nil, fmt.Errorf("schema: the root's type must be object")
	}
	for _, f := range []string{"apiVersion", "kind", "metadata"} {
		if _, ok := s.Properties[f]; ok {
			return nil, fmt.Errorf("schema: %s isn't the schema's to describe (every object has it)", f)
		}
	}
	plain, err := Env()
	if err != nil {
		return nil, err
	}
	trans, err := TransitionEnv()
	if err != nil {
		return nil, err
	}
	n, err := compile(envs{plain, trans}, s, "")
	if err != nil {
		return nil, err
	}
	return &Schema{root: n}, nil
}

func at(path string) string {
	if path == "" {
		return "schema"
	}
	return "schema " + path
}

func compile(env envs, s v1.JSONSchema, path string) (*node, error) {
	n := &node{s: s}
	switch {
	case s.Type == "" && !s.PreserveUnknown:
		return nil, fmt.Errorf("%s: needs a type (or x-kevaso-preserve-unknown: true)", at(path))
	case s.Type != "" && !slices.Contains(types, s.Type):
		return nil, fmt.Errorf("%s: type %q: want one of %s", at(path), s.Type, strings.Join(types, ", "))
	}
	if (len(s.Properties) > 0 || len(s.Required) > 0 || s.AdditionalProperties != nil) && s.Type != "object" {
		return nil, fmt.Errorf("%s: properties, required and additionalProperties are for objects", at(path))
	}
	if s.AdditionalProperties != nil && (len(s.Properties) > 0 || s.PreserveUnknown) {
		return nil, fmt.Errorf("%s: additionalProperties (a map) doesn't go with properties or x-kevaso-preserve-unknown", at(path))
	}
	if (s.Items != nil) != (s.Type == "array") {
		return nil, fmt.Errorf("%s: an array needs items, and only arrays have them", at(path))
	}
	if (s.Minimum != nil || s.Maximum != nil || s.ExclusiveMinimum || s.ExclusiveMaximum) && s.Type != "integer" && s.Type != "number" {
		return nil, fmt.Errorf("%s: minimum and maximum are for numbers", at(path))
	}
	if (s.ExclusiveMinimum && s.Minimum == nil) || (s.ExclusiveMaximum && s.Maximum == nil) {
		return nil, fmt.Errorf("%s: exclusiveMinimum/exclusiveMaximum need minimum/maximum", at(path))
	}
	if (s.MinLength != nil || s.MaxLength != nil || s.Pattern != "") && s.Type != "string" {
		return nil, fmt.Errorf("%s: minLength, maxLength and pattern are for strings", at(path))
	}
	if (s.MinItems != nil || s.MaxItems != nil) && s.Type != "array" {
		return nil, fmt.Errorf("%s: minItems and maxItems are for arrays", at(path))
	}
	if s.Pattern != "" {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: pattern: %v", at(path), err)
		}
		n.pattern = re
	}
	for _, r := range s.Required {
		if _, ok := s.Properties[r]; !ok && !s.PreserveUnknown {
			return nil, fmt.Errorf("%s: required %q isn't one of its properties", at(path), r)
		}
	}
	if len(s.Properties) > 0 {
		n.props = map[string]*node{}
		for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
			c, err := compile(env, s.Properties[name], join(path, name))
			if err != nil {
				return nil, err
			}
			n.props[name] = c
		}
	}
	var err error
	if s.Items != nil {
		if n.items, err = compile(env, *s.Items, path+"[]"); err != nil {
			return nil, err
		}
	}
	if s.AdditionalProperties != nil {
		if n.addl, err = compile(env, *s.AdditionalProperties, path+"[*]"); err != nil {
			return nil, err
		}
	}
	for i, r := range s.Validations {
		prg, err := CompileRule(env.plain, r.Rule)
		transition := false
		if err != nil { // a rule that compiles only with oldSelf is a transition rule
			if tprg, terr := CompileRule(env.transition, r.Rule); terr == nil {
				prg, err, transition = tprg, nil, true
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%s: x-kevaso-validations[%d]: %v", at(path), i, err)
		}
		if transition && strings.Contains(path, "[]") {
			return nil, fmt.Errorf("%s: x-kevaso-validations[%d]: oldSelf can't be used inside a list's items (an item has no old value to compare with): put the rule on the list", at(path), i)
		}
		n.rules = append(n.rules, rule{ValidationRule: r, prg: prg, transition: transition})
	}
	// enum values and the default must themselves be valid here (rules aside: they may need more).
	for i, e := range s.Enum {
		if errs := n.check(normalize(e), absent, path, false); len(errs) > 0 {
			return nil, fmt.Errorf("%s: enum[%d]: %s", at(path), i, errs[0])
		}
	}
	if s.Default != nil {
		if errs := n.check(normalize(s.Default), absent, path, false); len(errs) > 0 {
			return nil, fmt.Errorf("%s: default: %s", at(path), errs[0])
		}
	}
	return n, nil
}

// CompileRule compiles a CEL expression in env, bounded by CostLimit.
func CompileRule(env *cel.Env, expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("empty expression")
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast, cel.CostLimit(CostLimit))
}

func join(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}

// normalize deep-copies a value from JSON or YAML into the plain form (int64 for integers).
func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	out, err := v1.DecodeValue(b)
	if err != nil {
		return v
	}
	return out
}

// Part says which part of an object a write covers.
type Part int

const (
	// All checks every field (kinds without the status subresource).
	All Part = iota
	// Main checks everything but status (people's writes, when status is a subresource).
	Main
	// Status checks only status (a /status write).
	Status
)

// Default fills in the schema's defaults for missing fields, in place. It never makes a missing
// object just to put a default inside it.
func (s *Schema) Default(fields map[string]any, part Part) {
	for name, c := range s.root.props {
		if !covers(part, name) {
			continue
		}
		if _, ok := fields[name]; !ok && c.s.Default != nil {
			fields[name] = normalize(c.s.Default)
		}
		if v, ok := fields[name]; ok {
			c.defaults(v)
		}
	}
}

func covers(part Part, top string) bool {
	switch part {
	case Main:
		return top != "status"
	case Status:
		return top == "status"
	}
	return true
}

func (n *node) defaults(v any) {
	switch x := v.(type) {
	case map[string]any:
		for name, c := range n.props {
			if _, ok := x[name]; !ok && c.s.Default != nil {
				x[name] = normalize(c.s.Default)
			}
			if e, ok := x[name]; ok {
				c.defaults(e)
			}
		}
		if n.addl != nil {
			for _, e := range x {
				n.addl.defaults(e)
			}
		}
	case []any:
		if n.items != nil {
			for _, e := range x {
				n.items.defaults(e)
			}
		}
	}
}

// old is a node's value before an update, for transition rules (oldSelf); absent when there is
// none (a create, or a field the old object didn't have), and then they're skipped.
type old struct {
	v  any
	ok bool
}

var absent = old{}

func (o old) field(name string) old {
	if m, isMap := o.v.(map[string]any); o.ok && isMap {
		v, ok := m[name]
		return old{v, ok}
	}
	return absent
}

// Validate checks an object being created: fields are its top-level fields other than apiVersion,
// kind and metadata; full is the whole object, what root rules see as self. It returns every
// problem.
func (s *Schema) Validate(fields, full map[string]any, part Part) []string {
	return s.ValidateUpdate(fields, full, nil, nil, part)
}

// ValidateUpdate is Validate for an update, with the stored object's fields and whole object
// (nil on a create): transition rules compare each node with its old value.
func (s *Schema) ValidateUpdate(fields, full, oldFields, oldFull map[string]any, part Part) []string {
	var errs []string
	r := s.root
	prev, prevFull := absent, absent
	if oldFields != nil {
		prev, prevFull = old{oldFields, true}, old{oldFull, true}
	}
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if !covers(part, name) {
			continue
		}
		c, ok := r.props[name]
		switch {
		case ok:
			errs = append(errs, c.check(fields[name], prev.field(name), name, true)...)
		case !r.s.PreserveUnknown:
			errs = append(errs, fmt.Sprintf("%s: unknown field", name))
		}
	}
	for _, req := range r.s.Required {
		if _, ok := fields[req]; !ok && covers(part, req) {
			errs = append(errs, fmt.Sprintf("%s: required", req))
		}
	}
	if part != Status && len(errs) == 0 {
		errs = append(errs, evalRules(r.rules, full, prevFull, "")...)
	}
	return errs
}

func evalRules(rules []rule, self any, prev old, path string) []string {
	var errs []string
	for _, r := range rules {
		vars := map[string]any{"self": self}
		if r.transition {
			if !prev.ok {
				continue // nothing to compare with: a create, or a field that's new
			}
			vars["oldSelf"] = prev.v
		}
		msg := r.Message
		if msg == "" {
			msg = "failed rule: " + r.Rule
		}
		if path != "" {
			msg = path + ": " + msg
		}
		out, _, err := r.prg.Eval(vars)
		if err != nil {
			// A rule that can't evaluate counts as failed, so a malformed object never slips through.
			errs = append(errs, fmt.Sprintf("%s (%v)", msg, err))
			continue
		}
		if ok, isBool := out.Value().(bool); !isBool || !ok {
			errs = append(errs, msg)
		}
	}
	return errs
}

func (n *node) check(v any, prev old, path string, withRules bool) []string {
	fail := func(format string, args ...any) []string {
		return []string{path + ": " + fmt.Sprintf(format, args...)}
	}
	if v == nil {
		return fail("null isn't allowed (leave the field out)")
	}
	var errs []string
	switch n.s.Type {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return fail("want an object, got %s", typeName(v))
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			c, ok := n.props[k]
			switch {
			case ok:
				errs = append(errs, c.check(m[k], prev.field(k), join(path, k), withRules)...)
			case n.addl != nil: // a map's values keep their old ones by key
				errs = append(errs, n.addl.check(m[k], prev.field(k), path+"["+strconv.Quote(k)+"]", withRules)...)
			case !n.s.PreserveUnknown:
				errs = append(errs, fmt.Sprintf("%s: unknown field", join(path, k)))
			}
		}
		for _, r := range n.s.Required {
			if _, ok := m[r]; !ok {
				errs = append(errs, fmt.Sprintf("%s: required", join(path, r)))
			}
		}
	case "array":
		l, ok := v.([]any)
		if !ok {
			return fail("want a list, got %s", typeName(v))
		}
		if n.s.MinItems != nil && int64(len(l)) < *n.s.MinItems {
			errs = append(errs, fmt.Sprintf("%s: at least %d items", path, *n.s.MinItems))
		}
		if n.s.MaxItems != nil && int64(len(l)) > *n.s.MaxItems {
			errs = append(errs, fmt.Sprintf("%s: at most %d items", path, *n.s.MaxItems))
		}
		for i, e := range l {
			errs = append(errs, n.items.check(e, absent, fmt.Sprintf("%s[%d]", path, i), withRules)...)
		}
	case "string":
		s, ok := v.(string)
		if !ok {
			return fail("want a string, got %s", typeName(v))
		}
		size := int64(len([]rune(s)))
		if n.s.MinLength != nil && size < *n.s.MinLength {
			errs = append(errs, fmt.Sprintf("%s: at least %d characters", path, *n.s.MinLength))
		}
		if n.s.MaxLength != nil && size > *n.s.MaxLength {
			errs = append(errs, fmt.Sprintf("%s: at most %d characters", path, *n.s.MaxLength))
		}
		if n.pattern != nil && !n.pattern.MatchString(s) {
			errs = append(errs, fmt.Sprintf("%s: %q doesn't match %s", path, s, n.s.Pattern))
		}
	case "integer", "number":
		var f float64
		switch x := v.(type) {
		case int64:
			f = float64(x)
		case float64:
			if n.s.Type == "integer" {
				return fail("want an integer, got %v", x)
			}
			f = x
		default:
			return fail("want a%s, got %s", map[bool]string{true: "n integer", false: " number"}[n.s.Type == "integer"], typeName(v))
		}
		if mn := n.s.Minimum; mn != nil && (f < *mn || (n.s.ExclusiveMinimum && f == *mn)) {
			errs = append(errs, fmt.Sprintf("%s: %v is below the minimum %s", path, v, bound(*mn, n.s.ExclusiveMinimum)))
		}
		if mx := n.s.Maximum; mx != nil && (f > *mx || (n.s.ExclusiveMaximum && f == *mx)) {
			errs = append(errs, fmt.Sprintf("%s: %v is above the maximum %s", path, v, bound(*mx, n.s.ExclusiveMaximum)))
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fail("want true or false, got %s", typeName(v))
		}
	}
	if len(n.s.Enum) > 0 && !inEnum(v, n.s.Enum) {
		errs = append(errs, fmt.Sprintf("%s: must be one of %s", path, enumList(n.s.Enum)))
	}
	if withRules && len(errs) == 0 {
		errs = append(errs, evalRules(n.rules, v, prev, path)...)
	}
	return errs
}

func bound(f float64, exclusive bool) string {
	s := strconv.FormatFloat(f, 'g', -1, 64)
	if exclusive {
		return s + " (exclusive)"
	}
	return s
}

func typeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "an object"
	case []any:
		return "a list"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int64, float64:
		return "a number"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func inEnum(v any, enum []any) bool {
	b, _ := json.Marshal(v)
	for _, e := range enum {
		eb, _ := json.Marshal(normalize(e))
		if string(eb) == string(b) {
			return true
		}
	}
	return false
}

func enumList(enum []any) string {
	out := make([]string, len(enum))
	for i, e := range enum {
		b, _ := json.Marshal(e)
		out[i] = string(b)
	}
	return strings.ReplaceAll(strings.Join(out, ", "), `"`, "")
}
