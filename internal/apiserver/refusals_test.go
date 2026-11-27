package apiserver

import (
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
	"ClusterSecret":      `{"metadata":{"name":"k"},"spec":{"description":"bucket key"}}`,
	"Grant":              `{"metadata":{"name":"g","namespace":"d"},"spec":{"egress":[{"to":"10.0.0.0/8"}]}}`,
	"OpenShellPolicy":    `{"metadata":{"name":"p","namespace":"d"},"spec":{"networkPolicies":[{"name":"web","endpoints":[{"host":"example.com","port":443}]}]}}`,
	"IngressClass":       `{"metadata":{"name":"public"},"spec":{"controller":{"driver":"nginx","namespace":"kevaso-system","silo":"ingress"}}}`,
	"Ingress":            `{"metadata":{"name":"i","namespace":"d"},"spec":{"ingressClass":"public","hosts":["app.example.com"],"rules":[{"service":{"name":"web","port":"http"}}]}}`,
	"Issuer":             `{"metadata":{"name":"ca"},"spec":{"internalCA":true}}`,
	"Certificate":        `{"metadata":{"name":"c","namespace":"d"},"spec":{"hosts":["app.example.com"],"issuer":"ca","secretName":"c-tls"}}`,
	"Role":               `{"metadata":{"name":"r","namespace":"d"},"rules":[{"verbs":["get"],"resources":["silos"]}]}`,
	"ClusterRole":        `{"metadata":{"name":"r"},"rules":[{"verbs":["get"],"resources":["silos"]}]}`,
	"RoleBinding":        `{"metadata":{"name":"b","namespace":"d"},"roleRef":{"kind":"Role","name":"r"},"subjects":[{"kind":"User","name":"u"}]}`,
	"ClusterRoleBinding": `{"metadata":{"name":"b"},"roleRef":{"kind":"ClusterRole","name":"r"},"subjects":[{"kind":"User","name":"u"}]}`,
	"IP":                 `{"metadata":{"name":"ip","namespace":"d"},"spec":{"type":"Host","hostAddress":"mail"}}`,
	"IPSet":              `{"metadata":{"name":"ips","namespace":"d"},"spec":{"type":"Static","members":[{"ip":"a"},{"hostAddress":"b"}]}}`,
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
	{"Silo", []string{`spec.openshellPolicies=["Bad"]`}, "openshellPolicies: at most 32"},
	{"Silo", []string{`spec.openshellPolicies=["web","web"]`}, "openshellPolicies names must be unique"},
	{"Silo", []string{`spec.openshellPolicies=["web"]`}, "openshellPolicies is only for runtime"},
	{"SiloSet", []string{`spec.template.openshellPolicies=["web"]`}, "template: openshellPolicies is only for runtime"},
	{"Silo", []string{`spec.resources={"cpu":-1}`}, "spec.resources.cpu can't be negative"},
	{"Silo", []string{`spec.tolerations=[{"key":""}]`}, "every toleration needs a key"},
	{"Silo", []string{`spec.tolerations=[{"key":"k","effect":"NoExecute"}]`}, "toleration effect must be"},
	{"Silo", []string{`spec.init={"steps":[]}`}, "every init step needs a name and something to run"},
	{"Silo", []string{`spec.init={"when":"daily","steps":[{"name":"a","run":"true"}]}`}, "init.when must be firstBoot or everyBoot"},
	{"Silo", []string{`spec.init={"steps":[{"name":"a","run":"x"},{"name":"a","run":"y"}]}`}, "init step names must be unique"},
	{"Silo", []string{`spec.availability={"onHostLoss":"Pray"}`}, "availability.onHostLoss must be"},
	{"Silo", []string{`spec.availability={"onControlPlaneLoss":"Panic"}`}, "availability.onControlPlaneLoss must be Continue or Stop"},
	{"Silo", []string{`spec.availability={"onControlPlaneLoss":"Continue","after":"2m"}`}, "availability.after goes with onControlPlaneLoss: Stop"},
	{"Silo", []string{`spec.availability={"after":"2m"}`}, "availability.after goes with onControlPlaneLoss: Stop"},
	{"Silo", []string{`spec.availability={"onControlPlaneLoss":"Stop","after":"10s"}`}, "availability.after \"10s\": want a duration from 30s to 24h0m0s"},
	{"Silo", []string{`spec.availability={"onControlPlaneLoss":"Stop","after":"soon"}`}, "availability.after \"soon\": want a duration"},
	{"Silo", []string{`spec.volumes=[{"name":"Data","mountPath":"/d"}]`}, "every volume needs a name"},
	{"Silo", []string{`spec.volumes=[{"name":"d","mountPath":"/d:rw,z"}]`}, "every volume needs a name"},
	{"Silo", []string{`spec.volumes=[{"name":"d","mountPath":"/a/../b"}]`}, "every volume needs a name"},
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
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"name":"Api","ports":[{"port":"web"}]}]`}, `service Api: name "Api": lower-case letters`},
	{"Silo", []string{`spec.services=[{"ports":[{"port":"web"}]}]`}, `services[0]: ports[web]: "web" isn't a declared port`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web"},{"port":"web"}]}]`}, `services[0]: ports[web]: listed twice in one service`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web"}]},{"ports":[{"port":"web"}]}]`}, `services[0] and services[1] are both named s`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"name":"a"}]`}, `service a: no ports`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web","allowFrom":["a/b/c"]}]}]`}, `services[0]: ports[web].allowFrom: "a/b/c": a silo`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web","allowFrom":["10.0.0.0/8"]}]}]`}, `services[0]: ports[web].allowFrom: "10.0.0.0/8" is a network range`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"NodePort","ports":[{"port":"web"}]}]`}, `services[0]: type "NodePort": Internal`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","hostPort":{"worker":"public"},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort.worker "public": external or internal`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","hostPort":{"worker":"external","ip":"x"},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort takes exactly one of worker, ip and own (two ways in inside one service)`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","hostPort":{},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort: say one of worker`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","hostPort":{"own":true},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort.own is a SiloSet instance's own IPSet member`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","hostPort":{"ip":"ip/x"},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort.ip "ip/x": an IP's name in this namespace (no kind/ prefix)`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"hostPort":{"worker":"external"},"ports":[{"port":"web"}]}]`}, `services[0]: hostPort goes with type: HostPort; this one is Internal`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","loadBalancer":{"provider":"linode"},"ports":[{"port":"web"}]}]`}, `services[0]: loadBalancer goes with type: LoadBalancer; this one is HostPort`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"LoadBalancer","ports":[{"port":"web"}]}]`}, `services[0]: type LoadBalancer needs loadBalancer.provider`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"LoadBalancer","loadBalancer":{"provider":"Linode"},"ports":[{"port":"web"}]}]`}, `services[0]: loadBalancer.provider "Linode"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"LoadBalancer","loadBalancer":{"provider":"linode","ip":"lb/x"},"ports":[{"port":"web"}]}]`}, `services[0]: loadBalancer.ip "lb/x"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web","as":443}]}]`}, `services[0]: ports[web].as: only on a HostPort or LoadBalancer service`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"ports":[{"port":"web","sources":["10.0.0.0/8"]}]}]`}, `services[0]: ports[web].sources: only on a HostPort or LoadBalancer service`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"LoadBalancer","loadBalancer":{"provider":"linode"},"ports":[{"port":"web","lease":{"max":"1h"}}]}]`}, `services[0]: ports[web].lease: leases are on HostPort services only`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","as":70000}]}]`}, `services[0]: ports[web].as: 70000 isn't from 1 to 65535`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","as":6443}]}]`}, `6443 is the API, which a silo may not take`},
	{"SiloSet", []string{`spec.template.ports=[{"name":"web","port":80}]`, `spec.template.services=[{"type":"HostPort","ports":[{"port":"web","as":6443}]}]`}, `6443 is the API, which a silo may not take`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["10.0.0.0/33"]}]}]`}, `services[0]: ports[web].sources: "10.0.0.0/33"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["2001:db8::/32"]}]}]`}, `services[0]: ports[web].sources: "2001:db8::/32"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["2001:db8::1"]}]}]`}, `services[0]: ports[web].sources: "2001:db8::1"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["::ffff:10.0.0.1"]}]}]`}, `services[0]: ports[web].sources: "::ffff:10.0.0.1"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["fe80::1%eth0"]}]}]`}, `services[0]: ports[web].sources: "fe80::1%eth0"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["10.0.0.1, 10.0.0.2"]}]}]`}, `services[0]: ports[web].sources: "10.0.0.1, 10.0.0.2"`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":[""]}]}]`}, `services[0]: ports[web].sources: ""`},
	{"Silo", []string{`spec.ports=[{"name":"web","port":80}]`, `spec.services=[{"type":"HostPort","ports":[{"port":"web","sources":["10.0.0.0/8; drop"]}]}]`}, `services[0]: ports[web].sources: "10.0.0.0/8; drop"`},
	{"SiloSet", []string{`spec.template.ports=[{"name":"web","port":80}]`, `spec.template.services=[{"type":"HostPort","ports":[{"port":"web","sources":["2001:db8::/32"]}]}]`}, `services[0]: ports[web].sources: "2001:db8::/32": IPv6 comes later`},
	{"Silo", []string{`spec.ports=[{"name":"a","port":80},{"name":"b","port":81}]`, `spec.services=[{"name":"x","type":"HostPort","ports":[{"port":"a","as":443}]},{"name":"y","type":"HostPort","ports":[{"port":"b","as":443}]}]`}, `service y: ports[b]: 443/TCP on worker: external is x a's already`},
	{"Silo", []string{`spec.network={"egress":{"source":{"own":true}}}`}, `network.egress.source.own is a SiloSet instance's own IPSet member`},
	{"Silo", []string{`spec.network={"egress":{"source":{"ip":"a","own":true}}}`}, `network.egress.source takes exactly one of ip`},
	{"Silo", []string{`spec.network={"egress":{"source":{}}}`}, `network.egress.source takes exactly one of ip`},
	{"Silo", []string{`spec.network={"egress":{"source":{"ip":"A"}}}`}, `network.egress.source.ip "A"`},
	{"Grant", []string{`spec.egress=[{"to":"::ffff:203.0.113.7"}]`}, `an IPv4-mapped IPv6 address: write the IPv4 address (203.0.113.7)`},
	{"Grant", []string{`spec.egress=[{"to":"fe80::/64"}]`}, `which a grant never opens`},
	{"Grant", []string{`spec.egress=[{"to":"10.64.2.5"}]`}, "the silo range"},
	{"Grant", []string{`spec.egress=[{"to":"10.65.0.9"}]`}, "the service range"},
	{"Grant", []string{`spec.egress=[{"to":"10.63.0.4"}]`}, "the mesh range"},
	{"Grant", []string{`spec.egress=[{"to":"10.62.0.4"}]`}, "the mesh range"},
	{"Grant", []string{`spec.egress=[{"to":"127.0.0.1"}]`}, "loopback"},
	{"Grant", []string{`spec.egress=[{"to":"169.254.169.254"}]`}, "link-local"},
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
	{"SiloSet", []string{`spec.template.availability={"onControlPlaneLoss":"Stop","after":"5s"}`}, "availability.after \"5s\": want a duration from 30s"},
	{"SiloSet", []string{`metadata.name="` + strings.Repeat("a", 57) + `"`}, "a SiloSet's name is at most 56 characters"},
	{"SiloSet", []string{`spec.template.ports=[{"name":"web","port":80}]`, `spec.template.services=[{"type":"HostPort","hostPort":{"ip":"x"},"ports":[{"port":"web"}]}]`}, `template.services[0].hostPort.ip names IP x: one IP can't serve many instances`},
	{"SiloSet", []string{`spec.template.ports=[{"name":"web","port":80}]`, `spec.template.services=[{"type":"LoadBalancer","loadBalancer":{"provider":"linode","ip":"x"},"ports":[{"port":"web"}]}]`}, `template.services[0].loadBalancer.ip names IP x`},
	{"SiloSet", []string{`spec.template.network={"egress":{"source":{"ip":"x"}}}`}, `template.network.egress.source.ip names IP x`},
	{"SiloSet", []string{`spec.template.network={"egress":{"source":{"own":true}}}`}, `the template says own, so the set needs ips: SETNAME`},
	{"SiloSet", []string{`spec.ips="edge"`}, `spec.ips edge is only used with own`},
	{"SiloSet", []string{`spec.template.runtime="kvm"`}, "template: spec.runtime must be one of"},
	// Service
	{"Service", []string{`spec.selector={}`}, "spec.selector is required"},
	{"Service", []string{`spec.ports=[{"name":"web","port":0}]`}, "every port needs a name, a port from 1 to 65535"},
	{"Service", []string{`spec.ports=[{"name":"web","port":80},{"name":"web","port":81}]`}, "port names must be unique"},
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
	{"Secret", []string{`spec.generate="token"`, `spec.data={"token":"eA=="}`}, "spec.generate and spec.data don't go together"},
	{"Secret", []string{`spec.value="eA=="`}, `unknown field "value"`}, // gone: keys are always named (spec.data)
	{"Secret", []string{`spec.generate=true`}, "spec.generate"},        // it names the key it makes
	{"Secret", []string{`spec.type="registry"`, `spec.server="ghcr.io"`, `spec.username="bot"`, `spec.generate="password"`}, "a registry secret is never delivered to a silo (only a host's agent gets it, for a pull) and isn't generated"},
	// Grant
	{"Grant", []string{`spec.egress!`}, "a grant needs egress, secrets or operations"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"email"}]`}, "every grant secret needs a name, and deliver"},
	{"Grant", []string{`spec.secrets=[{"name":"k"}]`}, `secret k: key is required: name one key (key: KEY) or every key (key: "*")`},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"file"}]`}, `secret k: key is required: name one key (key: KEY) or every key (key: "*")`},
	{"Grant", []string{`spec.secrets=[{"name":"k","deliver":"inject","to":{"host":"a.example.com"}}]`}, "secret k: key is required: name the one key to inject (key: KEY)"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"*","deliver":"inject","to":{"host":"a.example.com"}}]`}, `secret k: inject adds one key: name it (key: KEY), not "*"`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"a/b"}]`}, `secret k: key "a/b": letters, digits, - _ and .`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"-x","deliver":"env"}]`}, `secret k: key "-x"`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"inject"}]`}, "deliver: inject needs to.host"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","to":{"host":"a.example.com"}}]`}, "to goes with deliver: inject"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","path":"/run/k"}]`}, "path goes with deliver: file"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","env":"K"}]`}, "env goes with deliver: env"},
	{"Grant", []string{`spec.operations={"sign":{"keyRef":""}}`}, "operations.sign needs a keyRef"},
	{"Grant", []string{`spec.requires={"assurance":"trust-me"}`}, "requires.assurance must be host, vtpm or confidential"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"file","path":"/run/k","approval":{"required":true}}]`}, "approval works with deliver: broker or inject"},
	{"Grant", []string{`spec.egress=[{"to":"not a host"}]`}, "egress"},
	{"OpenShellPolicy", []string{`spec.networkPolicies!`}, "an OpenShellPolicy needs 1 to 32"},
	{"OpenShellPolicy", []string{`spec.networkPolicies=[{"name":"Bad","endpoints":[{"host":"example.com","port":443}]}]`}, "every network policy needs a name"},
	{"OpenShellPolicy", []string{`spec.networkPolicies=[{"name":"web","endpoints":[{"host":"example.com","port":443}]},{"name":"web","endpoints":[{"host":"example.com","port":80}]}]`}, "network policy names must be unique"},
	{"OpenShellPolicy", []string{`spec.networkPolicies=[{"name":"web","endpoints":[]}]`}, "every network policy needs 1 to 16"},
	{"OpenShellPolicy", []string{`spec.networkPolicies=[{"name":"web","endpoints":[{"host":"example.com","port":0}]}]`}, "every endpoint needs a host"},
	{"OpenShellPolicy", []string{`spec.networkPolicies=[{"name":"web","endpoints":[{"host":"example.com","port":443}],"binaries":[]}]`}, "binaries, when set"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"inject","to":{"host":"*.example.com"}}]`}, `secret k: to.host "*.example.com" must be one host name`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"inject","to":{"host":"a.example.com","format":"Bearer"}}]`}, "secret k: to.format must contain {{value}} once"},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"inject","to":{"host":"a.example.com","header":"X: y"}}]`}, `secret k: to.header "X: y" isn't a header name`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"file","path":"/run/s,src=/,dst=/run/q/f"}]`}, `secret k: path "/run/s,src=/,dst=/run/q/f" must be under /run/`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"file","path":"/run/s/a:b"}]`}, `secret k: path "/run/s/a:b" must be under /run/`},
	{"Grant", []string{`spec.secrets=[{"name":"k","key":"k","deliver":"file","path":"/etc/k"}]`}, `secret k: path "/etc/k" must be under /run/`},
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
	{"Role", []string{`rules=[{"verbs":["get"],"resources":["clustersecrets"]}]`}, "a Role can't grant clustersecrets"},
	{"Role", []string{`rules=[{"verbs":["get"],"resources":["clustersecrets/value"]}]`}, "a Role can't grant clustersecrets"},
	{"ClusterRole", []string{`rules=[{"verbs":["get"]}]`}, "every rule needs verbs and resources"},
	{"Role", []string{`rules=[{"verbs":["sudo"],"resources":["silos"]}]`}, "verbs must be *, get, list"},
	{"ClusterRole", []string{`rules=[{"verbs":["get"],"resources":["silos/exec"],"selector":{"a":"b"}}]`}, "a rule's selector (by label) only works on secrets"},
	{"ClusterRoleBinding", []string{`roleRef.name=""`}, "roleRef.name is required"},
	{"RoleBinding", []string{`subjects=[]`}, "a binding needs at least one subject"},
	{"ClusterRoleBinding", []string{`subjects=[{"kind":"User","name":""}]`}, "every subject needs a name and a kind"},
	{"Service", []string{`spec.type="ClusterIP"`}, `type "ClusterIP": Internal`},
	{"Service", []string{`spec.type="HostPort"`}, `type HostPort arrives at the worker running one silo, so a Service of several can't be one`},
	{"Service", []string{`spec.type="LoadBalancer"`}, `type LoadBalancer needs loadBalancer.provider`},
	{"Service", []string{`spec.loadBalancer={"provider":"linode"}`}, `loadBalancer goes with type: LoadBalancer`},
	{"Service", []string{`spec.type="LoadBalancer"`, `spec.loadBalancer={"provider":"Linode"}`}, `loadBalancer.provider "Linode"`},
	{"RoleBinding", []string{`roleRef.kind="Group"`}, "roleRef.kind must be Role or ClusterRole"},
	{"ClusterRoleBinding", []string{`roleRef.kind="Role"`}, "a ClusterRoleBinding can only grant a ClusterRole"},
	{"RoleBinding", []string{`roleRef.name=""`}, "roleRef.name is required"},
	{"ClusterRoleBinding", []string{`subjects=[]`}, "a binding needs at least one subject"},
	{"RoleBinding", []string{`subjects=[{"kind":"Robot","name":"r"}]`}, "every subject needs a name and a kind"},
	// IP
	{"IP", []string{`spec.type!`}, `spec.type is required: Host`},
	{"IP", []string{`spec.type="Pool"`}, `spec.type "Pool": Host or Provider`},
	{"IP", []string{`spec.hostAddress!`}, `type Host needs hostAddress`},
	{"IP", []string{`spec.hostAddress="Mail"`}, `spec.hostAddress "Mail"`},
	{"IP", []string{`spec.region="us-ord"`}, `type Host is a host's address: provider and region are for type Provider`},
	{"IP", []string{`spec.type="Provider"`, `spec.hostAddress!`, `spec.provider="linode"`}, `type Provider needs provider and region`},
	{"IP", []string{`spec.type="Provider"`, `spec.provider="linode"`, `spec.region="us-ord"`}, `hostAddress is for type Host`},
	{"IP", []string{`spec.type="Provider"`, `spec.hostAddress!`, `spec.provider="Linode"`, `spec.region="us-ord"`}, `spec.provider "Linode"`},
	{"IPSet", []string{`spec.type!`}, `spec.type is required: Static`},
	{"IPSet", []string{`spec.type="Pool"`}, `spec.type "Pool": Static or Dynamic`},
	{"IPSet", []string{`spec.members=[]`}, `type Static needs members`},
	{"IPSet", []string{`spec.members=[{"ip":"a","hostAddress":"b"}]`}, `members[0]: exactly one of ip`},
	{"IPSet", []string{`spec.members=[{"ip":"a"},{"ip":"a"}]`}, `members[1]: ip: a is members[0] already`},
	{"IPSet", []string{`spec.max=3`}, `type Static lists its members: provider, region and max are for type Dynamic`},
	{"IPSet", []string{`spec.type="Dynamic"`, `spec.provider="linode"`, `spec.region="us-ord"`, `spec.max=2`}, `type Dynamic reserves provider IPs, so it can't have a host's address`},
	{"IPSet", []string{`spec.type="Dynamic"`, `spec.members!`, `spec.provider="linode"`}, `type Dynamic needs provider, region and max`},
	// Host
	{"Host", []string{`spec.internalIP!`}, "a host needs spec.internalIP"},
	{"Host", []string{`spec.components={}`}, "a host needs at least one component"},
	{"Host", []string{`spec.components.worker={"taints":[{"key":"k","effect":"NoExecute"}]}`}, "every taint needs a key and an effect"},
	{"Host", []string{`spec.components.worker={"runtimes":[{"name":"kvm"}]}`}, "unknown runtime in spec.components.worker.runtimes"},
	{"Host", []string{`spec.internalIP="fd00::1"`}, `spec.internalIP: "fd00::1" is IPv6: the internal IP is IPv4`},
	{"Host", []string{`spec.externalIP="2001:db8::5"`}, `spec.externalIP: "2001:db8::5" is IPv6: it goes in spec.externalIPv6`},
	{"Host", []string{`spec.externalIPv6="203.0.113.5"`}, `spec.externalIPv6: "203.0.113.5" is IPv4: it goes in spec.externalIP`},
	{"Host", []string{`spec.externalIPv6="fe80::1"`}, `spec.externalIPv6: "fe80::1" isn't a global IPv6 address`},
	{"IP", []string{`spec.family="IPv4+IPv6"`}, `spec.family "IPv4+IPv6": IPv4 (the default) or IPv6`},
	{"Host", []string{`spec.externalIP="10.0.0.5"`}, "spec.internalIP and spec.externalIP are the same address"},
	{"Host", []string{`spec.network={"dns":["mesh"]}`}, `spec.network.dns: "mesh": internal or external`},
	{"Host", []string{`spec.network={"dns":["external"]}`}, "spec.network.dns: external: the host has no external IP"},
	{"Host", []string{`spec.addresses=[{"name":"mail","kind":"external","address":"nope"}]`}, `spec.addresses[0]: "nope" isn't an address`},
	{"Host", []string{`spec.addresses=[{"name":"mail","kind":"external","address":"203.0.113.0/30"}]`}, `is a range: one address per name`},
	{"Host", []string{`spec.addresses=[{"name":"mail","kind":"public","address":"203.0.113.9"}]`}, `spec.addresses[0]: kind "public": external`},
	{"Host", []string{`spec.addresses=[{"name":"Mail","kind":"external","address":"203.0.113.9"}]`}, `spec.addresses[0]: name "Mail"`},
	{"Host", []string{`spec.addresses=[{"name":"a","kind":"external","address":"203.0.113.9"},{"name":"a","kind":"external","address":"203.0.113.10"}]`}, `spec.addresses[1]: a is listed twice`},
	{"Host", []string{`spec.addresses=[{"name":"a","kind":"internal","address":"10.0.0.5"}]`}, `spec.addresses[0]: 10.0.0.5 is its main IP already`},
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
