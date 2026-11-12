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
		{`!has(self.spec.availability) || !has(self.spec.availability.onHostLoss) || self.spec.availability.onHostLoss in ['Wait', 'Recreate', 'Move']`,
			"availability.onHostLoss must be Wait, Recreate or Move"},
		{`!has(self.spec.service) || !has(self.spec.service.expose) || self.spec.service.expose in ['private', 'hostPort', 'loadBalancer']`,
			"service.expose must be private, hostPort or loadBalancer"},
		{`!has(self.spec.service) || !has(self.spec.service.ports) || self.spec.service.ports.all(p, p.name != '' && p.port >= 1 && p.port <= 65535 && (!has(p.protocol) || p.protocol in ['TCP', 'UDP']))`,
			"every service port needs a name, a port from 1 to 65535, and protocol TCP or UDP"},
		{`!has(self.spec.service) || !has(self.spec.service.ports) || self.spec.service.ports.all(a, self.spec.service.ports.exists_one(b, b.name == a.name))`,
			"service port names must be unique"},
		{`!has(self.spec.service) || !has(self.spec.service.hostPort) || (has(self.spec.service.expose) && self.spec.service.expose == 'hostPort')`,
			"service.hostPort goes with expose: hostPort"},
		{`!has(self.spec.service) || !has(self.spec.service.hostPort) || !has(self.spec.service.hostPort.ports) || self.spec.service.hostPort.ports.all(n, has(self.spec.service.ports) && self.spec.service.ports.exists(p, p.name == n))`,
			"service.hostPort.ports must name ports of the service"},
		{`!has(self.spec.service) || !has(self.spec.service.expose) || self.spec.service.expose != 'loadBalancer' || (has(self.spec.service.loadBalancer) && self.spec.service.loadBalancer.class in ['worker-ip', 'ip-pool'])`,
			"expose: loadBalancer needs loadBalancer.class: worker-ip or ip-pool (cloud classes come with their plugins)"},
		{`!has(self.spec.service) || !has(self.spec.service.loadBalancer) || self.spec.service.loadBalancer.class != 'ip-pool' || (has(self.spec.service.loadBalancer.pool) && self.spec.service.loadBalancer.pool != '')`,
			"loadBalancer class ip-pool needs a pool"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source in ['host', 'sameAsService', 'pool']`,
			"network.egress.source must be host, sameAsService or pool (gateway comes later)"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source != 'sameAsService' || (has(self.spec.service) && has(self.spec.service.expose) && self.spec.service.expose in ['hostPort', 'loadBalancer'])`,
			"egress.source sameAsService needs a service exposed with hostPort or loadBalancer: there's no outside address to send from otherwise"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source != 'pool' || (has(self.spec.network.egress.pool) && self.spec.network.egress.pool != '')`,
			"egress.source pool needs a pool"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.pool) || !has(self.spec.service) || !has(self.spec.service.loadBalancer) || !has(self.spec.service.loadBalancer.pool) || self.spec.network.egress.pool == self.spec.service.loadBalancer.pool`,
			"a silo holds one pool address: egress.pool must be its loadBalancer's pool (or use egress.source: sameAsService)"},
		{`!has(self.spec.volumes) || self.spec.volumes.all(v, v.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') && v.mountPath.startsWith('/') && (!has(v.class) || v.class == 'local'))`,
			"every volume needs a name (lower-case letters, digits, -), an absolute mountPath, and class local (others come with their plugins)"},
		{`!has(self.spec.volumes) || self.spec.volumes.all(a, self.spec.volumes.exists_one(b, b.name == a.name))`,
			"volume names must be unique"},
		{`!has(self.spec.allowFrom) || self.spec.allowFrom.all(a, a.silo != '')`,
			"every allowFrom entry names a silo (NAME or NAMESPACE/NAME)"},
		{`!has(self.spec.availability) || !has(self.spec.availability.onHostLoss) || self.spec.availability.onHostLoss != 'Move'`,
			"onHostLoss: Move needs every disk on a movable storage class, and this silo's disk is local (host-bound): use Wait, or Recreate if its image is enough"},
	},
	"Secret": {
		{`!has(self.spec.type) || self.spec.type in ['opaque', 'ed25519', 'ecdsa-p256']`,
			"spec.type must be opaque, ed25519 or ecdsa-p256"},
		{`!has(self.spec.allowedDelivery) || self.spec.allowedDelivery.all(m, m in ['broker', 'inject', 'file', 'env', 'sign'])`,
			"spec.allowedDelivery: broker, inject, file, env or sign"},
		{`!has(self.spec.type) || self.spec.type == 'opaque' || !has(self.spec.valueReadable) || !self.spec.valueReadable`,
			"a signing key is never readable: drop valueReadable"},
		{`!has(self.spec.type) || self.spec.type == 'opaque' || !has(self.spec.allowedDelivery) || self.spec.allowedDelivery.all(m, m == 'sign')`,
			"a signing key is only used through sign: allowedDelivery can only be [sign]"},
		{`!has(self.spec.generate) || !self.spec.generate || !has(self.spec.value)`,
			"spec.generate and spec.value don't go together: the server makes the value"},
	},
	"Grant": {
		{`has(self.spec.egress) || has(self.spec.secrets) || has(self.spec.operations)`,
			"a grant needs egress, secrets or operations"},
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, s.name != '' && (!has(s.deliver) || s.deliver in ['broker', 'inject', 'file', 'env']))`,
			"every grant secret needs a name, and deliver: broker, inject, file or env (signing keys go in operations.sign)"},
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, !has(s.deliver) || s.deliver != 'inject' || (has(s.to) && s.to.host != ''))`,
			"deliver: inject needs to.host: the destination the gate adds it to"},
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, !has(s.to) || (has(s.deliver) && s.deliver == 'inject'))`,
			"to goes with deliver: inject"},
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, !has(s.path) || (has(s.deliver) && s.deliver == 'file'))`,
			"path goes with deliver: file"},
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, !has(s.env) || (has(s.deliver) && s.deliver in ['env', 'inject']))`,
			"env goes with deliver: env (or inject, on OpenShell: the variable holding the placeholder)"},
		{`!has(self.spec.operations) || !has(self.spec.operations.sign) || self.spec.operations.sign.keyRef != ''`,
			"operations.sign needs a keyRef"},
		{`!has(self.spec.requires) || !has(self.spec.requires.assurance) || self.spec.requires.assurance in ['host', 'vtpm', 'confidential']`,
			"requires.assurance must be host, vtpm or confidential"},
	},
	"IngressClass": {
		{`self.spec.controller.silo != '' && self.spec.controller.namespace != ''`, "spec.controller needs a silo and its namespace"},
	},
	"Ingress": {
		{`self.spec.ingressClass != ''`, "spec.ingressClass is required"},
		{`has(self.spec.hosts) && self.spec.hosts.size() > 0`, "spec.hosts needs at least one host name"},
		{`has(self.spec.rules) && self.spec.rules.size() > 0 && self.spec.rules.all(r, r.silo.name != '' && r.silo.port != '')`,
			"every rule needs a silo name and a port name"},
		{`self.spec.rules.all(r, !has(r.path) || r.path.startsWith('/'))`, "paths start with /"},
		{`!has(self.spec.tls) || !has(self.spec.tls.mode) || self.spec.tls.mode in ['acme', 'internal-ca', 'none']`,
			"tls.mode must be acme, internal-ca or none"},
	},
	"Issuer": {
		{`(has(self.spec.acme) ? 1 : 0) + (has(self.spec.internalCA) && self.spec.internalCA ? 1 : 0) + (has(self.spec.controller) && self.spec.controller != '' ? 1 : 0) == 1`,
			"an Issuer names one cert-controller: controller (with config), or the shorthand acme or internalCA"},
		{`!has(self.spec.acme) || self.spec.acme.server.startsWith('https://')`, "acme.server is an https:// directory URL"},
		{`!has(self.spec.acme) || !has(self.spec.acme.solvers) || self.spec.acme.solvers.all(s, (has(s.http01) ? 1 : 0) + (has(s.dns01) ? 1 : 0) == 1)`,
			"each acme solver is exactly one of http01 or dns01"},
		{`!has(self.spec.acme) || !has(self.spec.acme.solvers) || self.spec.acme.solvers.all(s, !has(s.dns01) || (has(s.dns01.provider) && s.dns01.provider != ''))`,
			"a dns01 solver names a DNS provider registered on the control plane"},
	},
	"Certificate": {
		{`has(self.spec.hosts) && self.spec.hosts.size() > 0`, "spec.hosts needs at least one host name"},
		{`self.spec.issuer != '' && self.spec.secretName != ''`, "spec.issuer and spec.secretName are required"},
	},
	"Role":               rbacRuleRules,
	"ClusterRole":        rbacRuleRules,
	"RoleBinding":        append([]Rule{{`self.roleRef.kind in ['Role', 'ClusterRole']`, "roleRef.kind must be Role or ClusterRole"}}, bindingRules...),
	"ClusterRoleBinding": append([]Rule{{`self.roleRef.kind == 'ClusterRole'`, "a ClusterRoleBinding can only grant a ClusterRole"}}, bindingRules...),
	"IPPool": {
		{`self.spec.host != ''`, "spec.host is required: the host these addresses are routed to"},
		{`has(self.spec.addresses) && self.spec.addresses.size() > 0`, "spec.addresses needs at least one address or range"},
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

var rbacRuleRules = []Rule{
	{`!has(self.rules) || self.rules.all(r, has(r.verbs) && r.verbs.size() > 0 && has(r.resources) && r.resources.size() > 0)`,
		"every rule needs verbs and resources"},
	{`!has(self.rules) || self.rules.all(r, r.verbs.all(v, v in ['*', 'get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'use', 'read-value', 'write']))`,
		"verbs must be *, get, list, watch, create, update, patch, delete, or for secrets use, read-value and write"},
	{`!has(self.rules) || self.rules.all(r, !has(r.selector) || r.resources.all(x, x == 'secrets'))`,
		"a rule's selector (by label) only works on secrets"},
}

var bindingRules = []Rule{
	{`self.roleRef.name != ''`, "roleRef.name is required"},
	{`has(self.subjects) && self.subjects.size() > 0`, "a binding needs at least one subject"},
	{`self.subjects.all(s, s.kind in ['User', 'Group', 'ServiceAccount'] && s.name != '')`,
		"every subject needs a name and a kind of User, Group or ServiceAccount"},
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
