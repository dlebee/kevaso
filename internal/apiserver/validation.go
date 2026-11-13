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
		{`!has(self.spec.service) || !has(self.spec.service.expose) || self.spec.service.expose != 'loadBalancer' || (has(self.spec.service.loadBalancer) && self.spec.service.loadBalancer.class.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'))`,
			"expose: loadBalancer needs loadBalancer.class: worker-ip, ip-pool, or a plugin's class (e.g. linode-nodebalancer)"},
		{`!has(self.spec.service) || !has(self.spec.service.loadBalancer) || !has(self.spec.service.loadBalancer.ip) || self.spec.service.loadBalancer.class != 'worker-ip'`,
			"loadBalancer.ip names an IP; worker-ip has none: its address is the host's"},
		{`!has(self.spec.service) || !has(self.spec.service.loadBalancer) || !has(self.spec.service.loadBalancer.dedicated) || !self.spec.service.loadBalancer.dedicated || (!has(self.spec.service.loadBalancer.ip) && self.spec.service.loadBalancer.class != 'worker-ip')`,
			"loadBalancer.dedicated asks for an IP made for it alone: not with loadBalancer.ip (that one is named already), nor on worker-ip (the host's address)"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source in ['host', 'sameAsService', 'pool']`,
			"network.egress.source must be host, sameAsService or pool (gateway comes later)"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source != 'sameAsService' || (has(self.spec.service) && has(self.spec.service.expose) && self.spec.service.expose in ['hostPort', 'loadBalancer'])`,
			"egress.source sameAsService needs a service exposed with hostPort or loadBalancer: there's no outside address to send from otherwise"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.source) || self.spec.network.egress.source != 'pool' || (has(self.spec.network.egress.ip) && self.spec.network.egress.ip != '') || (has(self.spec.service) && has(self.spec.service.loadBalancer) && self.spec.service.loadBalancer.class == 'ip-pool')`,
			"egress.source pool needs egress.ip: an IP of class ip-pool (or a load balancer of class ip-pool, whose IP it then sends from)"},
		{`!has(self.spec.network) || !has(self.spec.network.egress) || !has(self.spec.network.egress.ip) || (has(self.spec.network.egress.source) && self.spec.network.egress.source == 'pool')`,
			"egress.ip goes with egress.source: pool"},
		{`!has(self.spec.volumes) || self.spec.volumes.all(v, v.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') && v.mountPath.startsWith('/') && (!has(v.class) || v.class.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$')))`,
			"every volume needs a name (lower-case letters, digits, -), an absolute mountPath, and a class: local, or a plugin's (e.g. linode-block)"},
		{`!has(self.spec.volumes) || self.spec.volumes.all(v, !has(v.class) || v.class == 'local' || (has(v.size) && v.size != ''))`,
			"a volume on a plugin's storage class needs a size (e.g. 10Gi)"},
		{`!has(self.spec.volumes) || self.spec.volumes.all(a, self.spec.volumes.exists_one(b, b.name == a.name))`,
			"volume names must be unique"},
		{`!has(self.spec.allowFrom) || self.spec.allowFrom.all(a, a.silo != '')`,
			"every allowFrom entry names a silo (NAME or NAMESPACE/NAME)"},
		{`!has(self.spec.update) || !has(self.spec.update.strategy) || self.spec.update.strategy in ['StopFirst', 'StartFirst']`,
			"update.strategy must be StopFirst or StartFirst"},
		{`!has(self.spec.update) || !has(self.spec.update.strategy) || self.spec.update.strategy != 'StartFirst'`,
			"update.strategy StartFirst on a single silo needs its disk cloned, which comes with moves (M14); use StopFirst, or a SiloSet, whose update.strategy StartFirst starts extra instances first"},
		{`!has(self.spec.exclusive) || !self.spec.exclusive || !has(self.spec.availability) || !has(self.spec.availability.onHostLoss) || self.spec.availability.onHostLoss == 'Wait'`,
			"exclusive: true forbids automatic failover: onHostLoss must be Wait (a move is manual, once the old copy is provably stopped)"},
		{`!has(self.spec.daemons) || self.spec.daemons.all(d, d.name.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') && d.run != '' && (!has(d.restart) || d.restart in ['always', 'onFailure', 'never']))`,
			"every daemon needs a name (lower-case letters, digits, -), something to run, and restart: always, onFailure or never"},
		{`!has(self.spec.daemons) || self.spec.daemons.all(a, self.spec.daemons.exists_one(b, b.name == a.name))`,
			"daemon names must be unique"},
		{`!has(self.spec.upkeep) || self.spec.upkeep.all(u, u.name != '' && u.every != '' && u.check != '' && u.fix != '')`,
			"every upkeep task needs a name, every (e.g. 6h), a check and a fix"},
		{`!has(self.spec.upkeep) || self.spec.upkeep.all(a, self.spec.upkeep.exists_one(b, b.name == a.name))`,
			"upkeep names must be unique"},
		{`!has(self.spec.panes) || !has(self.spec.panes.allow) || self.spec.panes.allow.all(k, k in ['status', 'html'])`,
			"panes.allow: status, html"},
		{`!has(self.spec.panes) || !has(self.spec.panes.maxPanes) || (self.spec.panes.maxPanes >= 0 && self.spec.panes.maxPanes <= 16)`,
			"panes.maxPanes: 0 to 16"},
		{`!has(self.spec.imagePull) || (has(self.spec.imagePull.secretRef) && self.spec.imagePull.secretRef != '')`,
			"imagePull needs secretRef: a registry secret in the namespace"},
		{`!has(self.spec.placement) || !has(self.spec.placement.spread) || (self.spec.placement.spread.by in ['host', 'zone', 'region'] && has(self.spec.placement.spread.selector) && self.spec.placement.spread.selector.size() > 0)`,
			"placement.spread needs by (host, zone or region) and a selector"},
	},
	"Image": {
		{`has(self.spec.versions) && self.spec.versions.size() > 0`, "an image needs at least one version"},
		{`self.spec.versions.all(v, v.name.matches('^[A-Za-z0-9][-._A-Za-z0-9]*$'))`,
			"every version needs a name (letters, digits, '.', '_', '-')"},
		{`self.spec.versions.all(a, self.spec.versions.exists_one(b, b.name == a.name))`, "version names must be unique"},
		{`self.spec.versions.all(v, has(v.disk))`,
			"every version is a bootable disk (url and sha256): Images are machine disks for cloud-hypervisor; container silos name a registry reference instead"},
		{`self.spec.versions.all(v, !has(v.disk) || (v.disk.url.startsWith('https://') && v.disk.sha256.matches('^[0-9a-fA-F]{64}$')))`,
			"a disk needs an https:// url and its sha256 (64 hex digits): hosts check what they fetch"},
	},
	"SiloSet": {
		{`self.spec.instances >= 0 && (!has(self.spec.standby) || self.spec.standby >= 0)`, "instances and standby can't be negative"},
		{`!has(self.spec.spread) || self.spec.spread in ['host', 'zone', 'region']`, "spread must be host, zone or region"},
		{`!has(self.spec.upgradePolicy) || self.spec.upgradePolicy in ['Manual', 'Rolling']`, "upgradePolicy must be Manual or Rolling"},
		{`!has(self.spec.scaleInPolicy) || self.spec.scaleInPolicy in ['NewestFirst', 'OldestFirst']`, "scaleInPolicy must be NewestFirst or OldestFirst"},
		{`!has(self.spec.update) || !has(self.spec.update.strategy) || self.spec.update.strategy in ['StopFirst', 'StartFirst']`,
			"update.strategy must be StopFirst or StartFirst"},
		{`!has(self.spec.update) || ((!has(self.spec.update.maxUnavailable) || self.spec.update.maxUnavailable >= 0) && (!has(self.spec.update.maxSurge) || self.spec.update.maxSurge >= 0))`,
			"update.maxUnavailable and update.maxSurge can't be negative"},
		{`!has(self.spec.template.exclusive) || !self.spec.template.exclusive || !has(self.spec.update) || ((!has(self.spec.update.strategy) || self.spec.update.strategy == 'StopFirst') && (!has(self.spec.update.maxSurge) || self.spec.update.maxSurge == 0))`,
			"exclusive instances update one at a time, stop-first: never two copies, so no StartFirst or maxSurge"},
		{`!has(self.spec.template.labels) || self.spec.template.labels.all(k, !k.startsWith('kevaso.com/'))`,
			"template.labels can't use kevaso.com/ labels: the set sets those"},
		{`self.metadata.name.size() <= 56`, "a SiloSet's name is at most 56 characters (its instances add -N)"},
		{`!has(self.spec.template.service) || !has(self.spec.template.service.loadBalancer) || !has(self.spec.template.service.loadBalancer.ip)`,
			"template.service.loadBalancer.ip would put every instance on one IP with the same ports, which clash: leave it out and each instance gets one of its own (or put the set behind a Service, which can name one)"},
		{`!has(self.spec.template.network) || !has(self.spec.template.network.egress) || !has(self.spec.template.network.egress.ip)`,
			"template.network.egress.ip would give every instance the same IP, which serves one silo"},
	},
	"Service": {
		{`has(self.spec.selector) && self.spec.selector.size() > 0`, "spec.selector is required: the labels of the silos it serves"},
		{`has(self.spec.ports) && self.spec.ports.size() > 0 && self.spec.ports.all(p, p.name != '' && p.port >= 1 && p.port <= 65535 && (!has(p.protocol) || p.protocol in ['TCP', 'UDP']))`,
			"every port needs a name, a port from 1 to 65535, and protocol TCP or UDP"},
		{`self.spec.ports.all(a, self.spec.ports.exists_one(b, b.name == a.name))`, "port names must be unique"},
		{`!has(self.spec.type) || self.spec.type in ['ClusterIP', 'LoadBalancer']`, "type must be ClusterIP or LoadBalancer"},
		{`!has(self.spec.type) || self.spec.type != 'LoadBalancer' || (has(self.spec.loadBalancerClass) && self.spec.loadBalancerClass.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') && !(self.spec.loadBalancerClass in ['worker-ip', 'ip-pool']))`,
			"type LoadBalancer needs loadBalancerClass: a plugin's class (e.g. linode-nodebalancer); worker-ip and ip-pool are one host's addresses, so they're for a single silo's own service"},
		{`!has(self.spec.loadBalancerClass) || (has(self.spec.type) && self.spec.type == 'LoadBalancer')`,
			"loadBalancerClass goes with type: LoadBalancer"},
		{`!has(self.spec.loadBalancerIP) || (has(self.spec.type) && self.spec.type == 'LoadBalancer')`,
			"loadBalancerIP (an IP's name) goes with type: LoadBalancer"},
		{`!has(self.spec.loadBalancerDedicated) || !self.spec.loadBalancerDedicated || (has(self.spec.type) && self.spec.type == 'LoadBalancer' && !has(self.spec.loadBalancerIP))`,
			"loadBalancerDedicated asks for an IP of its own: with type LoadBalancer, and not with loadBalancerIP (that one is named already)"},
		{`!has(self.spec.routeWhen) || self.spec.routeWhen in ['ready', 'running']`,
			"routeWhen must be ready or running"},
	},
	"Secret": {
		{`!has(self.spec.type) || self.spec.type in ['opaque', 'ed25519', 'ecdsa-p256', 'registry']`,
			"spec.type must be opaque, ed25519, ecdsa-p256 or registry"},
		{`!has(self.spec.type) || self.spec.type != 'registry' || (has(self.spec.server) && self.spec.server != '' && has(self.spec.username) && self.spec.username != '')`,
			"a registry secret needs spec.server (the registry host, e.g. ghcr.io) and spec.username; its value is the password or token"},
		{`(has(self.spec.type) && self.spec.type == 'registry') || (!has(self.spec.server) && !has(self.spec.username))`,
			"spec.server and spec.username are for type: registry"},
		{`!has(self.spec.type) || self.spec.type != 'registry' || ((!has(self.spec.allowedDelivery) || self.spec.allowedDelivery.size() == 0) && (!has(self.spec.generate) || !self.spec.generate))`,
			"a registry secret is never delivered to a silo (only a host's agent gets it, for a pull) and isn't generated: drop allowedDelivery and generate"},
		{`!has(self.metadata.labels) || !('kevaso.com/default-pull' in self.metadata.labels) || (self.metadata.labels['kevaso.com/default-pull'] == 'true' && has(self.spec.type) && self.spec.type == 'registry')`,
			"kevaso.com/default-pull: \"true\", on a registry secret only (it makes it the namespace's pull secret for its server)"},
		{`!has(self.spec.allowedDelivery) || self.spec.allowedDelivery.all(m, m in ['broker', 'inject', 'file', 'env', 'sign'])`,
			"spec.allowedDelivery: broker, inject, file, env or sign"},
		{`!has(self.spec.type) || self.spec.type in ['opaque', 'registry'] || !has(self.spec.valueReadable) || !self.spec.valueReadable`,
			"a signing key is never readable: drop valueReadable"},
		{`!has(self.spec.type) || self.spec.type in ['opaque', 'registry'] || !has(self.spec.allowedDelivery) || self.spec.allowedDelivery.all(m, m == 'sign')`,
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
		{`!has(self.spec.secrets) || self.spec.secrets.all(s, !has(s.approval) || !has(s.approval.required) || !s.approval.required || !has(s.deliver) || s.deliver in ['broker', 'inject'])`,
			"approval works with deliver: broker or inject (and operations.sign): once a value sits in a file or an env var, nothing can ask again"},
	},
	"IngressClass": {
		{`has(self.spec.controller.driver) && self.spec.controller.driver != ''`, "spec.controller.driver names the proxy's driver (nginx, caddy, kong…)"},
		{`has(self.spec.controller.namespace) && self.spec.controller.namespace != '' && (has(self.spec.controller.silo) && self.spec.controller.silo != '' ? 1 : 0) + (has(self.spec.controller.siloSet) && self.spec.controller.siloSet != '' ? 1 : 0) == 1`,
			"spec.controller needs its namespace and one of silo or siloSet"},
	},
	"Ingress": {
		{`self.spec.ingressClass != ''`, "spec.ingressClass is required"},
		{`has(self.spec.hosts) && self.spec.hosts.size() > 0`, "spec.hosts needs at least one host name"},
		{`has(self.spec.rules) && self.spec.rules.size() > 0 && self.spec.rules.all(r, r.silo.name != '' && r.silo.port != '')`,
			"every rule needs a silo name and a port name"},
		{`self.spec.rules.all(r, !has(r.path) || r.path.startsWith('/'))`, "paths start with /"},
		{`!has(self.spec.tls) || (has(self.spec.tls.issuer) ? 1 : 0) + (has(self.spec.tls.secretName) ? 1 : 0) + (has(self.spec.tls.none) && self.spec.tls.none ? 1 : 0) <= 1`,
			"tls: at most one of issuer, secretName or none (none of them: the cluster's default issuer for the class)"},
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
	"IP": {
		{`self.spec.class.matches('^[a-z0-9]([-a-z0-9]*[a-z0-9])?$') && self.spec.class != 'worker-ip'`,
			"spec.class is required: ip-pool (a host's extra addresses) or a plugin's load-balancer class (worker-ip's address is the host's, not one to keep)"},
		{`!has(self.spec.reclaim) || self.spec.reclaim in ['Retain', 'Delete']`, "spec.reclaim must be Retain or Delete"},
		{`!has(self.spec.region) || self.spec.class != 'ip-pool'`, "spec.region is for a plugin's class; ip-pool's addresses are a host's (spec.host)"},
		{`!has(self.spec.host) || self.spec.class == 'ip-pool'`, "spec.host is for class ip-pool; a plugin's address is in a region (spec.region)"},
	},
	"Host": {
		{`(has(self.spec.internalIP) && self.spec.internalIP != '') || (has(self.spec.externalIP) && self.spec.externalIP != '')`,
			"a host needs spec.internalIP (its address on its own network), spec.externalIP (its address reachable from outside it), or both"},
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
	{`!has(self.rules) || self.rules.all(r, r.verbs.all(v, v in ['*', 'get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'use', 'read-value', 'write', 'approve', 'open']))`,
		"verbs must be *, get, list, watch, create, update, patch, delete, or for secrets use, read-value, write and approve, for ips use, or for silos/exposure open and approve"},
	{`!has(self.rules) || self.rules.all(r, !has(r.selector) || r.resources.all(x, x == 'secrets' || x == 'silos/exposure'))`,
		"a rule's selector (by label) only works on secrets and silos/exposure"},
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
