//go:build metal

package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
)

// TestMetalIngressUnknownHold is network-3's N3-5 (K-120, d5ff65b) on a real nginx class: an
// Ingress nginx refuses (a host past its server-name hash bucket) in another namespace, then
// nginx.conf is changed by hand outside any Ingress's part and reloaded. The class says at once
// (Applied False) that it doesn't end by itself and names that Ingress; nginx's config is left
// as the person made it, and still so 15 minutes later; deleting the Ingress applies the class
// again.
//
// Listens on the external IP while it runs: 80 and 443 (the nginx silo).
func TestMetalIngressUnknownHold(t *testing.T) {
	c := metal(t)
	ns, other := "heldweb", "heldother"
	c.namespace(ns, "ingress/site")
	c.namespace(other, "ingress/broken")
	t.Cleanup(func() {
		for _, a := range [][]string{{"delete", "ingress", "broken", "-n", other}, {"delete", "ingressclass", "public"}, {"delete", "silo", "ingress-public", "-n", "kevaso-system"}} {
			_, _ = c.kvo("", a...)
		}
	})
	name := "held." + strings.ReplaceAll(c.cfg.ExternalIP, ".", "-") + ".sslip.io"
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + name
	var o strings.Builder
	if code := kvoadm.Run(c.ctx, []string{"ingress", "install", "--host-port", "external", "--cluster", metalCluster,
		"--host", name + "=" + ns, "--host", long + "=" + other}, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm ingress install: exit %d\n%s", code, o.String())
	}
	c.apply(boxEcho(ns, "app", 8080) + `  ports: [{ name: http, port: 8080 }]
  service:
    ports: [{ port: http }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: site, namespace: ` + ns + ` }
spec:
  ingressClass: public
  hosts: [` + name + `]
  tls: { none: true }
  rules: [{ path: /, service: { name: app, port: http } }]
`)
	// The refused Ingress names a service in its own namespace. One that isn't there is omitted
	// from the render, not refused, and a hand edit with nothing left out is written back over.
	c.apply(boxEcho(other, "app", 8080) + `  ports: [{ name: http, port: 8080 }]
  service:
    ports: [{ port: http }]
`)
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-public")
	c.waitRunning(ns, 10*time.Minute, "app")
	c.waitRunning(other, 10*time.Minute, "app")
	class := func() *v1.IngressClass {
		var ic v1.IngressClass
		raw, _ := c.kvo("", "get", "ingressclass", "public", "-o", "json")
		if json.Unmarshal([]byte(raw), &ic) != nil {
			return &v1.IngressClass{}
		}
		return &ic
	}
	applied := func() *meta.Condition { return meta.FindCondition(class().Status.Conditions, "Applied") }
	c.eventually("the class applies", 3*time.Minute, func() (bool, string) {
		a := applied()
		return a != nil && a.Status == meta.ConditionTrue, fmt.Sprint(a)
	})
	// A host Kevaso takes and nginx refuses: longer than the hash bucket the driver sets
	// (server_names_hash_bucket_size 128; nginx -t: "could not build server_names_hash").
	// It is in place before the hand edit. A pass that sees the edit with nothing left out
	// writes its render back, and the unknown hold never starts.
	out, rc := c.kvo(`apiVersion: kevaso/v1
kind: Ingress
metadata:
  name: broken
  namespace: `+other+`
spec:
  ingressClass: public
  hosts: [`+long+`]
  rules: [{ path: /, service: { name: app, port: http } }]
`, "apply", "-f", "-")
	if rc != 0 {
		t.Fatalf("no Ingress nginx refuses could be made (a long host refused at admission): %s", strings.TrimSpace(out))
	}
	if !c.eventually("nginx refuses the long host", 2*time.Minute, func() (bool, string) {
		a := applied()
		return a != nil && a.Status == meta.ConditionFalse && strings.Contains(a.Message, "server_names_hash"), fmt.Sprint(a)
	}) {
		return
	}
	ctl := "$(docker ps -q --filter label=kevaso.com/name=ingress-public | head -1)"
	c.mustSh("docker exec " + ctl + " sh -c 'echo \"# by hand\" >> /etc/nginx/nginx.conf && nginx -s reload'")
	sum := func() string {
		return strings.TrimSpace(c.mustSh("docker exec " + ctl + " nginx -T 2>/dev/null | md5sum"))
	}
	time.Sleep(2 * time.Second)
	before := sum()
	editedAt := time.Now()
	held := func() (bool, string) {
		a := applied()
		return a != nil && a.Status == meta.ConditionFalse && strings.Contains(a.Message, "does not end by itself") && strings.Contains(a.Message, other+"/broken"), fmt.Sprint(a)
	}
	c.eventually("Applied False: it doesn't end by itself, naming the Ingress", 30*time.Second, held)
	t.Logf("held %s after the hand edit: %s", time.Since(editedAt).Round(time.Second), applied().Message)
	c.expect("nginx's config is as the person left it", sum(), before)
	c.holds("still held 15 minutes later, nginx unchanged", 15*time.Minute, func() (bool, string) {
		ok, why := held()
		if s := sum(); s != before {
			return false, "nginx -T changed: " + s
		}
		return ok, why
	})
	c.must("", "delete", "ingress", "broken", "-n", other)
	c.eventually("deleting the Ingress applies the class", 3*time.Minute, func() (bool, string) {
		a := applied()
		return a != nil && a.Status == meta.ConditionTrue, fmt.Sprint(a)
	})
}
