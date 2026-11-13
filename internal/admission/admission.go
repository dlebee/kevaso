// Package admission evaluates ValidationPolicy and MutationPolicy objects (design §4.1, ADR 0005):
// CEL over the object being written (`object`), the stored one (`oldObject`, null on create) and
// the request (`request`), matched by kind, namespace and operation.
//
// Order is fixed: mutation policies by name, each mutation in list order, each seeing the object as
// the ones before left it; then every validation policy by name, all of them, so a refusal lists
// every failure. A policy that can't be compiled or evaluated fails closed: it refuses every write
// it matches, naming itself.
package admission

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"google.golang.org/protobuf/types/known/structpb"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/schema"
)

// Exempt are the kinds no policy applies to: the policies themselves (a bad one can always be
// fixed) and RBAC (a policy can never lock people out).
var Exempt = []string{"ValidationPolicy", "MutationPolicy", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}

// Request is one write, in policy terms.
type Request struct {
	Operation string // CREATE | UPDATE
	User      string
	Groups    []string
	Verb      string // create | update
	Namespace string
	Name      string
	Kind      string // the object's kind: Silo, Database
	// Resource is the plural for built-ins (silos), PLURAL.GROUP for defined kinds.
	Resource string
	// BuiltIn: Kind and Resource both name a built-in kind.
	BuiltIn bool
}

func (r Request) value() map[string]any {
	groups := make([]any, len(r.Groups))
	for i, g := range r.Groups {
		groups[i] = g
	}
	return map[string]any{"operation": r.Operation, "user": r.User, "groups": groups, "verb": r.Verb,
		"namespace": r.Namespace, "name": r.Name, "kind": r.Kind, "resource": r.Resource}
}

// Env is the CEL environment of policies.
func Env() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("object", cel.DynType), cel.Variable("oldObject", cel.DynType), cel.Variable("request", cel.DynType))
}

type compiled struct {
	kind  string // ValidationPolicy | MutationPolicy
	name  string
	match v1.PolicyMatch
	err   error // compile error: fails closed
	vals  []compiledValidation
	muts  []compiledMutation
}

type compiledValidation struct {
	v1.PolicyValidation
	prg cel.Program
}

type compiledMutation struct {
	v1.Mutation
	path       []string
	value, cnd cel.Program
}

// Set is every policy, compiled and in order.
type Set struct {
	mutations, validations []*compiled
}

// Compile builds a Set. It never fails: a policy that doesn't compile is kept, and fails closed.
func Compile(vps []*v1.ValidationPolicy, mps []*v1.MutationPolicy) *Set {
	env, envErr := Env()
	s := &Set{}
	for _, p := range vps {
		c := &compiled{kind: "ValidationPolicy", name: p.Name, match: p.Spec.Match, err: envErr}
		if c.err == nil {
			c.vals, c.err = compileValidations(env, p.Spec)
		}
		s.validations = append(s.validations, c)
	}
	for _, p := range mps {
		c := &compiled{kind: "MutationPolicy", name: p.Name, match: p.Spec.Match, err: envErr}
		if c.err == nil {
			c.muts, c.err = compileMutations(env, p.Spec)
		}
		s.mutations = append(s.mutations, c)
	}
	byName := func(l []*compiled) { sort.Slice(l, func(i, j int) bool { return l[i].name < l[j].name }) }
	byName(s.validations)
	byName(s.mutations)
	return s
}

// CheckValidationPolicy says what's wrong with a policy before it's stored.
func CheckValidationPolicy(p *v1.ValidationPolicy) error {
	env, err := Env()
	if err != nil {
		return err
	}
	if err := checkMatch(p.Spec.Match); err != nil {
		return err
	}
	if len(p.Spec.Validations) == 0 {
		return fmt.Errorf("spec.validations: at least one")
	}
	_, err = compileValidations(env, p.Spec)
	return err
}

// CheckMutationPolicy says what's wrong with a policy before it's stored.
func CheckMutationPolicy(p *v1.MutationPolicy) error {
	env, err := Env()
	if err != nil {
		return err
	}
	if err := checkMatch(p.Spec.Match); err != nil {
		return err
	}
	if len(p.Spec.Mutations) == 0 {
		return fmt.Errorf("spec.mutations: at least one")
	}
	_, err = compileMutations(env, p.Spec)
	return err
}

func checkMatch(m v1.PolicyMatch) error {
	if len(m.Kinds) == 0 {
		return fmt.Errorf("spec.match.kinds: at least one (a kind, a plural, PLURAL.GROUP or *)")
	}
	for _, k := range m.Kinds {
		if slices.Contains(Exempt, k) {
			return fmt.Errorf("spec.match.kinds: policies never apply to %s", k)
		}
		if bk, ok := v1.Lookup(k); ok && slices.Contains(Exempt, bk.Kind) {
			return fmt.Errorf("spec.match.kinds: policies never apply to %s", bk.Kind)
		}
	}
	for _, op := range m.Operations {
		if op != v1.OperationCreate && op != v1.OperationUpdate {
			return fmt.Errorf("spec.match.operations: %q: want CREATE or UPDATE", op)
		}
	}
	return nil
}

func compileValidations(env *cel.Env, spec v1.ValidationPolicySpec) ([]compiledValidation, error) {
	out := make([]compiledValidation, 0, len(spec.Validations))
	for i, v := range spec.Validations {
		prg, err := schema.CompileRule(env, v.Expression)
		if err != nil {
			return nil, fmt.Errorf("spec.validations[%d]: %v", i, err)
		}
		out = append(out, compiledValidation{PolicyValidation: v, prg: prg})
	}
	return out, nil
}

func compileMutations(env *cel.Env, spec v1.MutationPolicySpec) ([]compiledMutation, error) {
	out := make([]compiledMutation, 0, len(spec.Mutations))
	for i, m := range spec.Mutations {
		path, err := FieldPath(m.Field)
		if err != nil {
			return nil, fmt.Errorf("spec.mutations[%d].field: %v", i, err)
		}
		cm := compiledMutation{Mutation: m, path: path}
		if cm.value, err = schema.CompileRule(env, m.Value); err != nil {
			return nil, fmt.Errorf("spec.mutations[%d].value: %v", i, err)
		}
		if m.When != "" {
			if cm.cnd, err = schema.CompileRule(env, m.When); err != nil {
				return nil, fmt.Errorf("spec.mutations[%d].when: %v", i, err)
			}
		}
		out = append(out, cm)
	}
	return out, nil
}

// FieldPath parses a mutation's field: dotted names, except that metadata.labels.KEY and
// metadata.annotations.KEY take the rest as one key (keys have dots: kevaso.com/x).
func FieldPath(f string) ([]string, error) {
	for _, p := range []string{"metadata.labels.", "metadata.annotations."} {
		if key, ok := strings.CutPrefix(f, p); ok {
			if key == "" {
				return nil, fmt.Errorf("%q: name the key", f)
			}
			return []string{"metadata", strings.TrimSuffix(strings.TrimPrefix(p, "metadata."), "."), key}, nil
		}
	}
	parts := strings.Split(f, ".")
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("%q: want a dotted path like spec.size", f)
		}
	}
	switch parts[0] {
	case "apiVersion", "kind", "status":
		return nil, fmt.Errorf("%q: a policy can't set %s", f, parts[0])
	case "metadata":
		return nil, fmt.Errorf("%q: of metadata, a policy sets only labels and annotations (metadata.labels.KEY)", f)
	}
	return parts, nil
}

func (c *compiled) matches(r Request) bool {
	if slices.Contains(Exempt, r.Kind) && r.BuiltIn {
		return false
	}
	kindOK := false
	for _, k := range c.match.Kinds {
		if k == "*" || k == r.Resource || (r.BuiltIn && k == r.Kind) {
			kindOK = true
			break
		}
	}
	if !kindOK {
		return false
	}
	if len(c.match.Namespaces) > 0 && (r.Namespace == "" || !slices.Contains(c.match.Namespaces, r.Namespace)) {
		return false
	}
	return len(c.match.Operations) == 0 || slices.Contains(c.match.Operations, r.Operation)
}

func (c *compiled) fail(format string, args ...any) error {
	return fmt.Errorf("%s %s: %s (policies fail closed: the write is refused until it's fixed)", c.kind, c.name, fmt.Sprintf(format, args...))
}

func vars(obj, old map[string]any, r Request) map[string]any {
	var o any = types.NullValue
	if old != nil {
		o = old
	}
	return map[string]any{"object": obj, "oldObject": o, "request": r.value()}
}

// Applies reports whether any policy matches the request (callers can skip the work otherwise).
func (s *Set) Applies(r Request) bool {
	for _, c := range append(slices.Clone(s.mutations), s.validations...) {
		if c.matches(r) {
			return true
		}
	}
	return false
}

// Mutate runs the matching mutation policies on obj, in place, and reports whether anything changed.
func (s *Set) Mutate(r Request, obj, old map[string]any) (bool, error) {
	changed := false
	for _, c := range s.mutations {
		if !c.matches(r) {
			continue
		}
		if c.err != nil {
			return changed, c.fail("%v", c.err)
		}
		for i, m := range c.muts {
			if m.cnd != nil {
				out, _, err := m.cnd.Eval(vars(obj, old, r))
				if err != nil {
					return changed, c.fail("mutations[%d].when: %v", i, err)
				}
				ok, isBool := out.Value().(bool)
				if !isBool {
					return changed, c.fail("mutations[%d].when isn't true or false", i)
				}
				if !ok {
					continue
				}
			}
			out, _, err := m.value.Eval(vars(obj, old, r))
			if err != nil {
				return changed, c.fail("mutations[%d].value: %v", i, err)
			}
			v, err := native(out)
			if err != nil {
				return changed, c.fail("mutations[%d].value: %v", i, err)
			}
			did, err := set(obj, m.path, v)
			if err != nil {
				return changed, c.fail("mutations[%d] (%s): %v", i, m.Field, err)
			}
			changed = changed || did
		}
	}
	return changed, nil
}

// Validate runs every matching validation policy and returns every failure, policy by policy.
func (s *Set) Validate(r Request, obj, old map[string]any) []string {
	var failed []string
	for _, c := range s.validations {
		if !c.matches(r) {
			continue
		}
		if c.err != nil {
			failed = append(failed, c.fail("%v", c.err).Error())
			continue
		}
		for i, v := range c.vals {
			out, _, err := v.prg.Eval(vars(obj, old, r))
			if err != nil {
				failed = append(failed, c.fail("validations[%d] can't be evaluated: %v", i, err).Error())
				continue
			}
			ok, isBool := out.Value().(bool)
			switch {
			case !isBool:
				failed = append(failed, c.fail("validations[%d] isn't true or false", i).Error())
			case !ok:
				msg := v.Message
				if msg == "" {
					msg = "failed: " + v.Expression
				}
				failed = append(failed, fmt.Sprintf("ValidationPolicy %s: %s", c.name, msg))
			}
		}
	}
	return failed
}

// native turns a CEL value into plain JSON values.
func native(v ref.Val) (any, error) {
	if v == types.NullValue {
		return nil, nil
	}
	pv, err := v.ConvertToNative(reflect.TypeFor[*structpb.Value]())
	if err != nil {
		return nil, fmt.Errorf("can't be stored as JSON: %v", err)
	}
	b, err := json.Marshal(pv.(*structpb.Value).AsInterface())
	if err != nil {
		return nil, err
	}
	return v1.DecodeValue(b)
}

// set puts v at path (nil removes it), making objects on the way, and reports whether it changed
// anything.
func set(obj map[string]any, path []string, v any) (bool, error) {
	cur := obj
	for i, p := range path[:len(path)-1] {
		next, ok := cur[p]
		if !ok || next == nil {
			if v == nil {
				return false, nil
			}
			m := map[string]any{}
			cur[p] = m
			cur = m
			continue
		}
		m, ok := next.(map[string]any)
		if !ok {
			return false, fmt.Errorf("%s isn't an object", strings.Join(path[:i+1], "."))
		}
		cur = m
	}
	last := path[len(path)-1]
	old, had := cur[last]
	if v == nil {
		delete(cur, last)
		return had, nil
	}
	if path[0] == "metadata" {
		if _, ok := v.(string); !ok {
			return false, fmt.Errorf("labels and annotations are strings")
		}
	}
	cur[last] = v
	return !had || !reflect.DeepEqual(old, v), nil
}
