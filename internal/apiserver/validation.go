package apiserver

import (
	"fmt"
	"strings"

	"cel.dev/cel-go/cel"
)

// Rule is a CEL validation rule over the object (`self`), like Kubernetes' x-kubernetes-validations.
// Built-in kinds use them, and KindDefinitions will declare their own (M17).
type Rule struct {
	Expr    string
	Message string
}

// builtinRules are the CEL rules of the built-in kinds. Field types, names and unknown fields are
// checked before these run (strict decoding into the Go types).
var builtinRules = map[string][]Rule{
	"Silo": {
		{`self.spec.runtime in ['cloud-hypervisor', 'openshell', 'docker', 'podman', 'openshell-container']`,
			"spec.runtime must be one of cloud-hypervisor, openshell, docker, podman, openshell-container"},
		{`!has(self.spec.resources) || !has(self.spec.resources.cpu) || self.spec.resources.cpu >= 0`,
			"spec.resources.cpu can't be negative"},
		{`!has(self.spec.tolerations) || self.spec.tolerations.all(t, t.key != '')`,
			"every toleration needs a key"},
		{`!has(self.spec.tolerations) || self.spec.tolerations.all(t, !has(t.effect) || t.effect in ['NoSchedule', 'PreferNoSchedule'])`,
			"toleration effect must be NoSchedule or PreferNoSchedule"},
		{`!has(self.spec.init) || (has(self.spec.init.steps) && self.spec.init.steps.size() > 0 && self.spec.init.steps.all(s, s.name != '' && s.run != ''))`,
			"every init step needs a name and something to run"},
		{`!has(self.spec.init) || !has(self.spec.init.when) || self.spec.init.when in ['firstBoot', 'everyBoot']`,
			"init.when must be firstBoot or everyBoot"},
		{`!has(self.spec.init) || !has(self.spec.init.steps) || self.spec.init.steps.all(a, self.spec.init.steps.exists_one(b, b.name == a.name))`,
			"init step names must be unique"},
	},
	"Host": {
		{`self.spec.address != ''`, "spec.address is required"},
		{`has(self.spec.components.controlPlane) || has(self.spec.components.worker)`,
			"a host needs at least one component: controlPlane or worker"},
		{`!has(self.spec.components.worker) || !has(self.spec.components.worker.taints) || self.spec.components.worker.taints.all(t, t.key != '' && t.effect in ['NoSchedule', 'PreferNoSchedule'])`,
			"every taint needs a key and an effect of NoSchedule or PreferNoSchedule (there's no NoExecute: silos are stateful)"},
		{`!has(self.spec.components.worker) || !has(self.spec.components.worker.runtimes) || self.spec.components.worker.runtimes.all(r, r.name in ['cloud-hypervisor', 'openshell', 'docker', 'podman', 'openshell-container'])`,
			"unknown runtime in spec.components.worker.runtimes"},
	},
}

type compiledRule struct {
	rule Rule
	prg  cel.Program
}

// validator evaluates the CEL rules of each kind.
type validator struct {
	rules map[string][]compiledRule
}

func newValidator(rules map[string][]Rule) (*validator, error) {
	env, err := cel.NewEnv(cel.Variable("self", cel.DynType))
	if err != nil {
		return nil, err
	}
	v := &validator{rules: map[string][]compiledRule{}}
	for kind, rs := range rules {
		for _, r := range rs {
			ast, iss := env.Compile(r.Expr)
			if iss != nil && iss.Err() != nil {
				return nil, fmt.Errorf("%s rule %q: %w", kind, r.Expr, iss.Err())
			}
			prg, err := env.Program(ast)
			if err != nil {
				return nil, fmt.Errorf("%s rule %q: %w", kind, r.Expr, err)
			}
			v.rules[kind] = append(v.rules[kind], compiledRule{rule: r, prg: prg})
		}
	}
	return v, nil
}

// validate returns every failed rule's message (nil when all pass).
func (v *validator) validate(kind string, obj map[string]any) []string {
	var failed []string
	for _, cr := range v.rules[kind] {
		out, _, err := cr.prg.Eval(map[string]any{"self": obj})
		if err != nil {
			// A rule that can't evaluate (a field missing where it expected one) counts as failed,
			// with the error, so a malformed object never slips through.
			failed = append(failed, fmt.Sprintf("%s (%v)", cr.rule.Message, err))
			continue
		}
		if ok, isBool := out.Value().(bool); !isBool || !ok {
			failed = append(failed, cr.rule.Message)
		}
	}
	return failed
}

func joinMessages(ms []string) string { return strings.Join(ms, "; ") }
