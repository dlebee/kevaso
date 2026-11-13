package apiserver

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Every refusal the built-in kinds document (builtinRules' messages, checkPorts and semantic) has a
// case here that writes the smallest object breaking that one rule and finds its message in the
// answer, starting from an object that is admitted. TestEveryRuleHasARefusal fails when a rule is
// added without one.

// base are objects each kind admits.
var base = map[string]string{
	"Silo":               `{"metadata":{"name":"s","namespace":"d"},"spec":{"runtime":"docker","container":{"image":"nginx:1.27"}}}`,
	"VMImage":            `{"metadata":{"name":"u","namespace":"d"},"spec":{"versions":[{"name":"v1","disk":{"url":"https://example.com/u.img","sha256":"` + strings.Repeat("ab", 32) + `"}}]}}`,
	"SiloSet":            `{"metadata":{"name":"set","namespace":"d"},"spec":{"instances":1,"template":{"runtime":"docker","container":{"image":"nginx:1.27"}}}}`,
	"Service":            `{"metadata":{"name":"svc","namespace":"d"},"spec":{"selector":{"app":"a"},"ports":[{"name":"web","port":80}]}}`,
	"Secret":             `{"metadata":{"name":"k","namespace":"d"},"spec":{}}`,
	"Grant":              `{"metadata":{"name":"g","namespace":"d"},"spec":{"egress":[{"to":"10.0.0.0/8"}]}}`,
	"IngressClass":       `{"metadata":{"name":"public"},"spec":{"controller":{"driver":"nginx","namespace":"kevaso-system","silo":"ingress"}}}`,
	"Ingress":            `{"metadata":{"name":"i","namespace":"d"},"spec":{"ingressClass":"public","hosts":["app.example.com"],"rules":[{"service":{"name":"web","port":"http"}}]}}`,
	"Issuer":             `{"metadata":{"name":"ca"},"spec":{"internalCA":true}}`,
	"Certificate":        `{"metadata":{"name":"c","namespace":"d"},"spec":{"hosts":["app.example.com"],"issuer":"ca","secretName":"c-tls"}}`,
	"Role":               `{"metadata":{"name":"r","namespace":"d"},"rules":[{"verbs":["get"],"resources":["silos"]}]}`,
	"ClusterRole":        `{"metadata":{"name":"r"},"rules":[{"verbs":["get"],"resources":["silos"]}]}`,
	"RoleBinding":        `{"metadata":{"name":"b","namespace":"d"},"roleRef":{"kind":"Role","name":"r"},"subjects":[{"kind":"User","name":"u"}]}`,
	"ClusterRoleBinding": `{"metadata":{"name":"b"},"roleRef":{"kind":"ClusterRole","name":"r"},"subjects":[{"kind":"User","name":"u"}]}`,
	"IP":                 `{"metadata":{"name":"ip","namespace":"d"},"spec":{"class":"ip-pool"}}`,
	"Host":               `{"metadata":{"name":"h"},"spec":{"internalIP":"10.0.0.5","components":{"worker":{}}}}`,
	"Namespace":          `{"metadata":{"name":"d"}}`,
}

// refusal is one rule broken: set (path=JSON; path! deletes) applied to the kind's base object.
type refusal struct {
	kind string
	set  []string
	want string // the start of the message, as the rule writes it
}

var refusals = []refusal{
	// Silo
	{"Silo", []string{`spec.runtime="kvm"`}, "spec.runtime must be one of"},
	{"Silo", []string{`spec.resources={"cpu":-1}`}, "spec.resources.cpu can't be negative"},
	{"Silo", []string{`spec.tolerations=[{"key":""}]`}, "every toleration needs a key"},
	{"Silo", []string{`spec.tolerations=[{"key":"k","effect":"NoExecute"}]`}, "toleration effect must be"},
	{"Silo", []string{`spec.init={"steps":[]}`}, "every init step needs a name and something to run"},
	{"Silo", []string{`spec.init={"when":"daily","steps":[{"name":"a","run":"true"}]}`}, "init.when must be firstBoot or everyBoot"},
	{"Silo", []string{`spec.init={"steps":[{"name":"a","run":"x"},{"name":"a","run":"y"}]}`}, "init step names must be unique"},
	{"Silo", []string{`spec.availability={"onHostLoss":"Pray"}`}, "availability.onHostLoss must be"},
	{"Silo", []string{`spec.network={"egress":{"source":"gateway"}}`}, "network.egress.source must be"},
	{"Silo", []string{`spec.network={"egress":{"ip":"x"}}`}, "egress.ip goes with egress.source: pool"},
	{"Silo", []string{`spec.volumes=[{"name":"Data","mountPath":"/d"}]`}, "every volume needs a name"},
	{"Silo", []string{`spec.volumes=[{"name":"d","class":"linode-block","mountPath":"/d"}]`}, "a volume on a plugin's storage class needs a size"},
	{"Silo", []string{`spec.volumes=[{"name":"d","mountPath":"/a"},{"name":"d","mountPath":"/b"}]`}, "volume names must be unique"},
	{"Silo", []string{`spec.update={"strategy":"Yolo"}`}, "update.strategy must be StopFirst or StartFirst"},
	{"Silo", []string{`spec.update={"strategy":"StartFirst"}`}, "update.strategy StartFirst on a single silo"},
	{"Silo", []string{`spec.exclusive=true`, `spec.availability={"onHostLoss":"Move"}`}, "exclusive: true forbids automatic failover"},
	{"Silo", []string{`spec.daemons=[{"name":"d","run":"x","restart":"sometimes"}]`}, "every daemon needs a name"},
	{"Silo", []string{`spec.daemons=[{"name":"d","run":"x"},{"name":"d","run":"y"}]`}, "daemon names must be unique"},
	{"Silo", []string{`spec.upkeep=[{"name":"u","every":"6h","check":"true","fix":""}]`}, "every upkeep task needs"},
	{"Silo", []string{`spec.upkeep=[{"name":"u","every":"6h","check":"c","fix":"f"},{"name":"u","every":"6h","check":"c","fix":"f"}]`}, "upkeep names must be unique"},
	{"Silo", []string{`spec.upkeep=[{"name":"u","every":"10s","check":"c","fix":"f"}]`}, "upkeep u: every \"10s\": want a duration of at least 1m"},
	{"Silo", []string{`spec.panes={"allow":["js"],"http":{"port":8080}}`}, "panes.allow: status, html"},
	{"Silo", []string{`spec.panes={"maxPanes":17,"http":{"port":8080}}`}, "panes.maxPanes: 0 to 16"},
	{"Silo", []string{`spec.panes={"maxPanes":1}`}, "panes needs http.port"},
	{"Silo", []string{`spec.panes={"http":{"port":8080,"path":"/x?y"}}`}, "panes.http.path: an absolute path"},
	{"Silo", []string{`spec.container.pull={"secretRef":""}`}, "container.pull needs secretRef"},
	{"Silo", []string{`spec.placement={"spread":{"by":"rack","selector":{"a":"b"}}}`}, "placement.spread needs by"},
	// Silo: ports and service (checkPorts)
	{"Silo", []string{`spec.ports=[{"name":"Web","port":80}]`}, `spec.ports: "Web": a port needs a name`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80},{"name":"web","port":81}]`}, "spec.ports: web is declared twice"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":0}]`}, "spec.ports[web]: port 0 isn't from 1 to 65535"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80,"protocol":"SCTP"}]`}, `spec.ports[web]: protocol "SCTP": TCP or UDP`},
	{"Silo", []string{`spec.ports=[{"name":"a","port":80},{"name":"b","port":80}]`}, "spec.ports: a and b are both 80/TCP"},
	{"Silo", []string{`spec.network={"egress":{"source":"sameAsService"}}`}, "network.egress.source sameAsService needs a service with a port"},
	{"Silo", []string{`spec.service={"name":"Api"}`}, `service.name "Api": lower-case letters`},
	{"Silo", []string{`spec.service={"ports":[{"port":"web"}]}`}, `service.ports[web]: "web" isn't a declared port`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web"},{"port":"web"}]}`}, "service.ports[web]: opened twice"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","allowFrom":["a/b/c"]}]}`}, `service.ports[web].allowFrom: "a/b/c": a silo`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","allowFrom":["10.0.0.0/8"]}]}`}, `service.ports[web].allowFrom: "10.0.0.0/8" is a network range`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","hostPort":["public"]}]}`}, `service.ports[web].hostPort: "public": internal or external`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","hostPort":["external","external"]}]}`}, "service.ports[web].hostPort: external twice"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","as":443}]}`}, "service.ports[web].as: only with hostPort or loadBalancer"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","sources":["10.0.0.0/8"]}]}`}, "service.ports[web].sources: only with hostPort or loadBalancer"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","hostPort":["external"],"as":70000}]}`}, "service.ports[web].as: 70000 isn't from 1 to 65535"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","hostPort":["external"],"sources":["10.0.0.0/33"]}]}`}, `service.ports[web].sources: "10.0.0.0/33" isn't an address or CIDR`},
	{"Silo", []string{`spec.ports=[{"name":"a","port":80},{"name":"b","port":81}]`, `spec.service={"ports":[{"port":"a","hostPort":["external"],"as":443},{"port":"b","hostPort":["external"],"as":443}]}`}, "service.ports[b]: 443/TCP on the external IP is a's already"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","loadBalancer":true}]}`}, "a port with loadBalancer: true needs service.loadBalancer.class"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web"}],"loadBalancer":{"class":"ip-pool"}}`}, "service.loadBalancer is where ports with loadBalancer: true get their address"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web","loadBalancer":true}],"loadBalancer":{"class":"ip-pool","ip":"x","dedicated":true}}`}, "service.loadBalancer.dedicated asks for an IP made for it alone"},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.service={"ports":[{"port":"web"}]}`, `spec.network={"egress":{"source":"sameAsService"}}`}, "network.egress.source sameAsService needs a port on the host or a load balancer"},
	{"Silo", []string{`spec.network={"egress":{"source":"pool"}}`}, "network.egress.source pool needs egress.ip"},
	// VMImage
	{"VMImage", []string{`spec.versions=[]`}, "a VMImage needs at least one version"},
	{"VMImage", []string{`spec.versions.0.name="-v"`}, "every version needs a name"},
	{"VMImage", []string{`spec.versions=[{"name":"v1","disk":{"url":"https://a/b","sha256":"` + strings.Repeat("ab", 32) + `"}},{"name":"v1","disk":{"url":"https://a/c","sha256":"` + strings.Repeat("cd", 32) + `"}}]`}, "version names must be unique"},
	{"VMImage", []string{`spec.versions.0.disk!`}, "every version is a bootable disk"},
	{"VMImage", []string{`spec.versions.0.disk.url="http://example.com/u.img"`}, "a disk needs an https:// url and its sha256"},
	// SiloSet
	{"SiloSet", []string{`spec.instances=-1`}, "instances and standby can't be negative"},
	{"SiloSet", []string{`spec.spread="rack"`}, "spread must be host, zone or region"},
	{"SiloSet", []string{`spec.upgradePolicy="Auto"`}, "upgradePolicy must be Manual or Rolling"},
	{"SiloSet", []string{`spec.scaleInPolicy="Random"`}, "scaleInPolicy must be NewestFirst or OldestFirst"},
	{"SiloSet", []string{`spec.update={"strategy":"Yolo"}`}, "update.strategy must be StopFirst or StartFirst"},
	{"SiloSet", []string{`spec.update={"maxSurge":-1}`}, "update.maxUnavailable and update.maxSurge can't be negative"},
	{"SiloSet", []string{`spec.template.exclusive=true`, `spec.update={"maxSurge":1}`}, "exclusive instances update one at a time"},
	{"SiloSet", []string{`spec.template.labels={"kevaso.com/set":"x"}`}, "template.labels can't use kevaso.com/ labels"},
	{"SiloSet", []string{`metadata.name="` + strings.Repeat("a", 57) + `"`}, "a SiloSet's name is at most 56 characters"},
	{"SiloSet", []string{`spec.template.ports=[{"name":"web","port":80}]`, `spec.template.service={"ports":[{"port":"web","loadBalancer":true}],"loadBalancer":{"class":"ip-pool","ip":"x"}}`}, "template.service.loadBalancer.ip would put every instance on one IP"},
	{"SiloSet", []string{`spec.template.service={"name":"api"}`}, "template.service.name would give every instance the same name"},
	{"SiloSet", []string{`spec.template.network={"egress":{"source":"pool","ip":"x"}}`}, "template.network.egress.ip would give every instance the same IP"},
	{"SiloSet", []string{`spec.template.runtime="kvm"`}, "template: spec.runtime must be one of"},
	// Service
	{"Service", []string{`spec.selector={}`}, "spec.selector is required"},
	{"Service", []string{`spec.ports=[{"name":"web","port":0}]`}, "every port needs a name, a port from 1 to 65535"},
	{"Service", []string{`spec.ports=[{"name":"web","port":80},{"name":"web","port":81}]`}, "port names must be unique"},
	{"Service", []string{`spec.type="NodePort"`}, "type must be ClusterIP or LoadBalancer"},
	{"Service", []string{`spec.type="LoadBalancer"`, `spec.loadBalancerClass="ip-pool"`}, "type LoadBalancer needs loadBalancerClass: a plugin's class"},
	{"Service", []string{`spec.loadBalancerClass="linode-nodebalancer"`}, "loadBalancerClass goes with type: LoadBalancer"},
	{"Service", []string{`spec.loadBalancerIP="x"`}, "loadBalancerIP (an IP's name) goes with type: LoadBalancer"},
	{"Service", []string{`spec.loadBalancerDedicated=true`}, "loadBalancerDedicated asks for an IP of its own"},
	{"Service", []string{`spec.routeWhen="always"`}, "routeWhen must be ready or running"},
	{"Service", []string{`spec.ports.0.targetPort="Http"`}, `port web: targetPort "Http": the name of a port`},
	// Secret
	{"Secret", []string{`spec.type="rsa"`}, "spec.type must be opaque, ed25519, ecdsa-p256 or registry"},
	{"Secret", []string{`spec.type="registry"`}, "a registry secret needs spec.server"},
	{"Secret", []string{`spec.server="ghcr.io"`}, "spec.server and spec.username are for type: registry"},
	{"Secret", []string{`spec.type="registry"`, `spec.server="ghcr.io"`, `spec.username="bot"`, `spec.allowedDelivery=["env"]`}, "a registry secret is never delivered to a silo"},
	{"Secret", []string{`metadata.labels={"kevaso.com/default-pull":"true"}`}, "kevaso.com/default-pull: \"true\", on a registry secret only"},
	{"Secret", []string{`spec.allowedDelivery=["email"]`}, "spec.allowedDelivery: broker, inject, file, env or sign"},
	{"Secret", []string{`spec.type="ed25519"`, `spec.valueReadable=true`}, "a signing key is never readable"},
	{"Secret", []string{`spec.type="ed25519"`, `spec.allowedDelivery=["env"]`}, "a signing key is only used through sign"},
	{"Secret", []string{`spec.generate=true`, `spec.value="eA=="`}, "spec.generate and spec.value don't go together"},
	{"Secret", []string{`spec.value="` + base64.StdEncoding.EncodeToString(make([]byte, 64<<10+1)) + `"`}, "spec.value: at most 64 KiB"},
	// Grant
	{"Grant", []string{`spec.egress!`}, "a grant needs egress, secrets or operations"},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"email"}]`}, "every grant secret needs a name, and deliver"},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"inject"}]`}, "deliver: inject needs to.host"},
	{"Grant", []string{`spec.secrets=[{"name":"k","to":{"host":"a.example.com"}}]`}, "to goes with deliver: inject"},
	{"Grant", []string{`spec.secrets=[{"name":"k","path":"/run/k"}]`}, "path goes with deliver: file"},
	{"Grant", []string{`spec.secrets=[{"name":"k","env":"K"}]`}, "env goes with deliver: env"},
	{"Grant", []string{`spec.operations={"sign":{"keyRef":""}}`}, "operations.sign needs a keyRef"},
	{"Grant", []string{`spec.requires={"assurance":"trust-me"}`}, "requires.assurance must be host, vtpm or confidential"},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"file","path":"/run/k","approval":{"required":true}}]`}, "approval works with deliver: broker or inject"},
	{"Grant", []string{`spec.egress=[{"to":"not a host"}]`}, "egress"},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"inject","to":{"host":"*.example.com"}}]`}, `secret k: to.host "*.example.com" must be one host name`},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"inject","to":{"host":"a.example.com","format":"Bearer"}}]`}, "secret k: to.format must contain {{value}} once"},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"inject","to":{"host":"a.example.com","header":"X: y"}}]`}, `secret k: to.header "X: y" isn't a header name`},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"file","path":"/etc/k"}]`}, `secret k: path "/etc/k" must be under /run/`},
	// IngressClass
	{"IngressClass", []string{`spec.controller.driver=""`}, "spec.controller.driver names the proxy's driver"},
	{"IngressClass", []string{`spec.controller.siloSet="ingress"`}, "spec.controller needs its namespace and one of silo or siloSet"},
	// Ingress
	{"Ingress", []string{`spec.ingressClass=""`}, "spec.ingressClass is required"},
	{"Ingress", []string{`spec.hosts=[]`}, "spec.hosts needs at least one host name"},
	{"Ingress", []string{`spec.rules=[{"service":{"name":"web","port":""}}]`}, "every rule needs a service"},
	{"Ingress", []string{`spec.rules.0.path="api"`}, "paths start with /"},
	{"Ingress", []string{`spec.tls={"issuer":"a","secretName":"b"}`}, "tls: at most one of issuer, secretName or none"},
	{"Ingress", []string{`spec.hosts=["10.0.0.1"]`}, `spec.hosts: "10.0.0.1" isn't a host name`},
	// Issuer
	{"Issuer", []string{`spec.controller="acme"`}, "an Issuer names one cert-controller"},
	{"Issuer", []string{`spec.internalCA!`, `spec.acme={"server":"http://acme.example.com/dir"}`}, "acme.server is an https:// directory URL"},
	{"Issuer", []string{`spec.internalCA!`, `spec.acme={"server":"https://acme.example.com/dir","solvers":[{}]}`}, "each acme solver is exactly one of http01 or dns01"},
	{"Issuer", []string{`spec.internalCA!`, `spec.acme={"server":"https://acme.example.com/dir","solvers":[{"dns01":{"provider":""}}]}`}, "a dns01 solver names a DNS provider"},
	// Certificate
	{"Certificate", []string{`spec.hosts=[]`}, "spec.hosts needs at least one host name"},
	{"Certificate", []string{`spec.issuer=""`}, "spec.issuer and spec.secretName are required"},
	{"Certificate", []string{`spec.hosts=["a b"]`}, `spec.hosts: "a b" isn't a host name`},
	// RBAC
	{"Role", []string{`rules=[{"verbs":[],"resources":["silos"]}]`}, "every rule needs verbs and resources"},
	{"ClusterRole", []string{`rules=[{"verbs":["sudo"],"resources":["silos"]}]`}, "verbs must be *, get, list"},
	{"Role", []string{`rules=[{"verbs":["get"],"resources":["silos"],"selector":{"a":"b"}}]`}, "a rule's selector (by label) only works on secrets"},
	{"ClusterRole", []string{`rules=[{"verbs":["get"]}]`}, "every rule needs verbs and resources"},
	{"Role", []string{`rules=[{"verbs":["sudo"],"resources":["silos"]}]`}, "verbs must be *, get, list"},
	{"ClusterRole", []string{`rules=[{"verbs":["get"],"resources":["silos/exec"],"selector":{"a":"b"}}]`}, "a rule's selector (by label) only works on secrets"},
	{"ClusterRoleBinding", []string{`roleRef.name=""`}, "roleRef.name is required"},
	{"RoleBinding", []string{`subjects=[]`}, "a binding needs at least one subject"},
	{"ClusterRoleBinding", []string{`subjects=[{"kind":"User","name":""}]`}, "every subject needs a name and a kind"},
	{"RoleBinding", []string{`roleRef.kind="Group"`}, "roleRef.kind must be Role or ClusterRole"},
	{"ClusterRoleBinding", []string{`roleRef.kind="Role"`}, "a ClusterRoleBinding can only grant a ClusterRole"},
	{"RoleBinding", []string{`roleRef.name=""`}, "roleRef.name is required"},
	{"ClusterRoleBinding", []string{`subjects=[]`}, "a binding needs at least one subject"},
	{"RoleBinding", []string{`subjects=[{"kind":"Robot","name":"r"}]`}, "every subject needs a name and a kind"},
	// IP
	{"IP", []string{`spec.class="Pool"`}, "spec.class is required"},
	{"IP", []string{`spec.reclaim="Keep"`}, "spec.reclaim must be Retain or Delete"},
	{"IP", []string{`spec.region="ca-central"`}, "spec.region is for a plugin's class"},
	{"IP", []string{`spec.class="linode-nodebalancer"`, `spec.host="h"`}, "spec.host is for class ip-pool"},
	{"IP", []string{`spec.address="10.0.0.300"`}, `spec.address: "10.0.0.300" isn't an address`},
	// Host
	{"Host", []string{`spec.internalIP!`}, "a host needs spec.internalIP"},
	{"Host", []string{`spec.components={}`}, "a host needs at least one component"},
	{"Host", []string{`spec.components.worker={"taints":[{"key":"k","effect":"NoExecute"}]}`}, "every taint needs a key and an effect"},
	{"Host", []string{`spec.components.worker={"runtimes":[{"name":"kvm"}]}`}, "unknown runtime in spec.components.worker.runtimes"},
	{"Host", []string{`spec.internalIP="fd00::1"`}, `spec.internalIP: "fd00::1" isn't an IPv4 address`},
	{"Host", []string{`spec.externalIP="10.0.0.5"`}, "spec.internalIP and spec.externalIP are the same address"},
	{"Host", []string{`spec.network={"dns":["mesh"]}`}, `spec.network.dns: "mesh": internal or external`},
	{"Host", []string{`spec.network={"dns":["external"]}`}, "spec.network.dns: external: the host has no external IP"},
	{"Host", []string{`spec.network={"addresses":["nope"]}`}, "spec.network.addresses: "},
	// Namespace
	{"Namespace", []string{`metadata.name="mesh"`}, `"mesh" is a network's name`},
	{"Namespace", []string{`metadata.name="internal"`}, `"internal" is a network's name`},
	{"Namespace", []string{`metadata.name="external"`}, `"external" is a network's name`},
}

// setPath sets (or with a trailing !, deletes) a dotted path in a JSON object.
func setPath(t *testing.T, m map[string]any, expr string) {
	t.Helper()
	path, val, isSet := strings.Cut(expr, "=")
	del := !isSet && strings.HasSuffix(path, "!")
	path = strings.TrimSuffix(path, "!")
	parts := strings.Split(path, ".")
	var cur any = m
	for i, p := range parts {
		last := i == len(parts)-1
		switch c := cur.(type) {
		case map[string]any:
			if last {
				if del {
					delete(c, p)
					return
				}
				var v any
				if err := json.Unmarshal([]byte(val), &v); err != nil {
					t.Fatalf("%s: %v", expr, err)
				}
				c[p] = v
				return
			}
			if _, ok := c[p]; !ok {
				c[p] = map[string]any{}
			}
			cur = c[p]
		case []any:
			n, err := strconv.Atoi(p)
			if err != nil || n >= len(c) {
				t.Fatalf("%s: no element %s", expr, p)
			}
			if last {
				if del {
					t.Fatalf("%s: can't delete an element", expr)
				}
				var v any
				_ = json.Unmarshal([]byte(val), &v)
				c[n] = v
				return
			}
			cur = c[n]
		default:
			t.Fatalf("%s: %s isn't an object", expr, p)
		}
	}
}

func objectOf(t *testing.T, kind string, set []string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(base[kind]), &m); err != nil {
		t.Fatalf("base %s: %v", kind, err)
	}
	m["apiVersion"], m["kind"] = v1.APIVersion, kind
	for _, s := range set {
		setPath(t, m, s)
	}
	b, _ := json.Marshal(m)
	return b
}

func admitJSON(t *testing.T, s *Server, kind string, b []byte) error {
	t.Helper()
	k, ok := v1.Lookup(kind)
	if !ok {
		t.Fatalf("no kind %s", kind)
	}
	obj, err := decodeStrict(b, k)
	if err != nil {
		return err
	}
	_, err = s.admit(kind, obj)
	return err
}

func TestRefusals(t *testing.T) {
	v, err := newValidator(builtinRules)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{valid: v}
	for kind := range base {
		if err := admitJSON(t, s, kind, objectOf(t, kind, nil)); err != nil {
			t.Errorf("the base %s is refused: %v", kind, err)
		}
	}
	for _, c := range refusals {
		err := admitJSON(t, s, c.kind, objectOf(t, c.kind, c.set))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %v: %v; want a refusal saying %q", c.kind, c.set, err, c.want)
		}
	}
}

// Every CEL rule of a built-in kind is broken by some case above, by its message.
func TestEveryRuleHasARefusal(t *testing.T) {
	var missing []string
	for kind, rules := range builtinRules {
		for _, r := range rules {
			found := false
			for _, c := range refusals {
				k := c.kind
				want := c.want
				if k == "SiloSet" && strings.HasPrefix(want, "template: ") {
					k, want = "Silo", strings.TrimPrefix(want, "template: ")
				}
				if k == kind && strings.HasPrefix(r.Message, want) {
					found = true
				}
			}
			if !found {
				missing = append(missing, fmt.Sprintf("%s: %s", kind, r.Message))
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("rules with no refusal case in refusals_test.go:\n%s", strings.Join(missing, "\n"))
	}
}
