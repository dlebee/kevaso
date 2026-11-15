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

// TestMetalIngressUnknownHold is network-3's N3-5 (K-120, d5ff65b) on a real nginx class: its
// nginx.conf changed by hand outside any Ingress's part and reloaded, then an Ingress nginx
// refuses (a host past its server-name hash bucket) in another namespace. The class says at once (Applied False) that it doesn't end by
// itself and names that Ingress; nginx's config is left as the person made it, and still so 15
// minutes later; deleting the Ingress applies the class again.
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
	var o strings.Builder
	if code := kvoadm.Run(c.ctx, []string{"ingress", "install", "--host-port", "external", "--context", metalCluster}, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm ingress install: exit %d\n%s", code, o.String())
	}
	name := "held." + strings.ReplaceAll(c.cfg.ExternalIP, ".", "-") + ".sslip.io"
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
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-public")
	c.waitRunning(ns, 10*time.Minute, "app")
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
	ctl := "$(docker ps -q --filter label=kevaso.com/name=ingress-public | head -1)"
	c.mustSh("docker exec " + ctl + " sh -c 'echo \"# by hand\" >> /etc/nginx/nginx.conf && nginx -s reload'")
	sum := func() string {
		return strings.TrimSpace(c.mustSh("docker exec " + ctl + " nginx -T 2>/dev/null | md5sum"))
	}
	time.Sleep(2 * time.Second)
	before := sum()
	// A host Kevaso takes and nginx refuses: longer than nginx's server-name hash bucket
	// (nginx -t: "could not build server_names_hash").
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + name
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
	madeAt := time.Now()
	held := func() (bool, string) {
		a := applied()
		return a != nil && a.Status == meta.ConditionFalse && strings.Contains(a.Message, "does not end by itself") && strings.Contains(a.Message, other+"/broken"), fmt.Sprint(a)
	}
	c.eventually("Applied False: it doesn't end by itself, naming the Ingress", 30*time.Second, held)
	t.Logf("held %s after the Ingress: %s", time.Since(madeAt).Round(time.Second), applied().Message)
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
