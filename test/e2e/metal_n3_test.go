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

// TestMetalInjectCutOff is network-3's N3-3 (K-076, a35d179): a microVM with an injected key; the
// host's own API traffic dropped (nft, output to 6443) for 2m30s. Its requests are still injected
// all through (past the one-minute refetch), and the journal says "injecting what it gave" once.
// The hour's end isn't waited for.
//
// Listens on nothing outside.
func TestMetalInjectCutOff(t *testing.T) {
	c := metal(t)
	ns := "cutinject"
	c.namespace(ns, "secret/api-key")
	key := randomValue(t, "sk-cut-")
	c.must(key, "create", "secret", "api-key", "-n", ns, "--from-file", "-", "--allow", "inject", "--write-only")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: api, namespace: ` + ns + ` }
spec:
  egress: [{ to: "` + metalInetAddr + `/32", ports: ["443"] }]
  secrets:
    - { name: api-key, deliver: inject, to: { host: ` + metalInetName + ` } }
---
` + vmEcho(ns, "vm", 8080) + "  grants: [api]\n")
	c.waitRunning(ns, 20*time.Minute, "vm")
	call := func() string {
		out, _ := c.in(ns, "vm", `ca=; [ -f /etc/ssl/certs/kevaso-ca-bundle.crt ] && ca="--cacert /etc/ssl/certs/kevaso-ca-bundle.crt"; `+
			"curl -sS --max-time 20 $ca --resolve "+metalInetName+":443:203.0.113.9 https://"+metalInetName+"/v1/models 2>&1")
		return out
	}
	want := `"auth": "` + metalHash("Bearer "+key) + `"`
	c.expect("injected before the cut", call(), want)
	since := strings.TrimSpace(c.mustSh("date -u '+%Y-%m-%d %H:%M:%S'"))
	t.Cleanup(func() { _, _ = c.sh("nft delete table inet kvtest 2>/dev/null; true") })
	c.mustSh("nft add table inet kvtest; nft add chain inet kvtest o '{ type filter hook output priority 0; }'; nft add rule inet kvtest o tcp dport 6443 drop")
	cut := time.Now()
	for _, at := range []time.Duration{30 * time.Second, 90 * time.Second, 150 * time.Second} {
		time.Sleep(time.Until(cut.Add(at)))
		got := call()
		if !strings.Contains(got, want) {
			t.Errorf("%s into the cut: not injected: %s", at, strings.TrimSpace(got))
		} else {
			t.Logf("%s into the cut: injected", at)
		}
	}
	c.mustSh("nft delete table inet kvtest")
	lines := c.mustSh("journalctl -u kevasod --no-pager --since '" + since + "' | grep 'injecting what it gave' || true")
	t.Logf("the journal:\n%s", lines)
	if n := strings.Count(strings.TrimSpace(lines), "\n") + 1; strings.TrimSpace(lines) == "" || n != 1 {
		t.Errorf("%d 'injecting what it gave' lines, want 1", map[bool]int{true: 0, false: n}[strings.TrimSpace(lines) == ""])
	}
	c.eventually("the API back for the host", 3*time.Minute, func() (bool, string) { return c.hostReady(metalHost) })
}

// TestMetalIngressUnknownHold is network-3's N3-5 (K-120, d5ff65b) on a real nginx class: its
// nginx.conf changed by hand outside any Ingress's part and reloaded, then an Ingress nginx
// refuses in another namespace. The class says at once (Applied False) that it doesn't end by
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
	sum := func() string { return strings.TrimSpace(c.mustSh("docker exec " + ctl + " nginx -T 2>/dev/null | md5sum")) }
	time.Sleep(2 * time.Second)
	before := sum()
	out, rc := c.kvo(`apiVersion: kevaso/v1
kind: Ingress
metadata:
  name: broken
  namespace: `+other+`
  annotations: { nginx/proxy-body-size: "lots; return 500" }
spec:
  ingressClass: public
  hosts: [broken.`+name+`]
  rules: [{ path: /, service: { name: app, port: http } }]
`, "apply", "-f", "-")
	if rc != 0 {
		t.Fatalf("no Ingress nginx refuses could be made (refused at admission): %s", strings.TrimSpace(out))
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
