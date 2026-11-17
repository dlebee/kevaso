//go:build metal

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLabOpenShellPolicy is an OpenShellPolicy on a pair lab, the same env file as
// TestMetalOpenShell. The ubuntu image has no curl, so the silo is born on a policy that can
// reach the Ubuntu archives, installs curl, and is then pointed at a read-only GET of
// https://example.com/. A POST and a path the rule does not name are refused by the proxy.
// Detaching the policy (the silo's list) refuses the curl, and deleting the policy while the
// silo still lists it falls back to deny-all.
func TestLabOpenShellPolicy(t *testing.T) {
	c := metal(t)
	ns := "ospol"
	c.namespace(ns)
	c.enableWorker("cloud-hypervisor", "docker", "openshell", "openshell-container")
	t.Cleanup(func() { c.enableWorker("cloud-hypervisor", "docker") })
	c.runtimeReady("openshell", 25*time.Minute)

	silo := func(policies string) string {
		extra := ""
		if policies != "" {
			extra = "  openshellPolicies: [" + policies + "]\n"
		}
		return fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: %s }
spec:
  runtime: openshell
  container: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 1Gi }
%s`, ns, extra)
	}
	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: OpenShellPolicy
metadata: { name: apt, namespace: %s }
spec:
  networkPolicies:
    - name: apt
      endpoints:
        - { host: archive.ubuntu.com, port: 80 }
        - { host: archive.ubuntu.com, port: 443 }
        - { host: security.ubuntu.com, port: 80 }
        - { host: security.ubuntu.com, port: 443 }
---
%s`, ns, silo("apt")))
	c.waitRunning(ns, 35*time.Minute, "box")
	if out, code := c.in(ns, "box", "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl"); code != 0 {
		t.Fatalf("install curl: %s", out)
	}

	c.apply(fmt.Sprintf(`apiVersion: kevaso/v1
kind: OpenShellPolicy
metadata: { name: example, namespace: %s }
spec:
  networkPolicies:
    - name: web
      endpoints:
        - host: example.com
          port: 443
          protocol: rest
          path: /
          access: read-only
---
%s`, ns, silo("example")))
	get := `curl -sS -o /tmp/ex -w '%{http_code}' https://example.com/; echo; cat /tmp/ex`
	post := `curl -sS -o /tmp/ex -w '%{http_code}' -X POST https://example.com/; echo; cat /tmp/ex`
	other := `curl -sS -o /tmp/ex -w '%{http_code}' https://example.com/not-allowed; echo; cat /tmp/ex`
	allowed := func(out string, code int) bool {
		return code == 0 && strings.Contains(out, "200") && strings.Contains(out, "Example Domain")
	}
	// A proxy that let the request through shows the origin: the page, a 405, or its 404.
	// A refusal is curl failing, or a body that is none of those.
	refused := func(out string, code int) bool {
		origin := strings.Contains(out, "Example Domain") || strings.Contains(out, "405") || strings.Contains(out, "Not Found")
		return code != 0 || !origin
	}
	c.eventually("GET https://example.com/ is allowed", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return allowed(out, code), fmt.Sprintf("exit %d %s", code, out)
	})
	if out, code := c.in(ns, "box", post); !refused(out, code) {
		t.Fatalf("POST was not refused by the proxy: exit %d %s", code, out)
	}
	if out, code := c.in(ns, "box", other); !refused(out, code) {
		t.Fatalf("a path the rule does not allow was not refused: exit %d %s", code, out)
	}

	c.apply(silo(""))
	c.eventually("detached: curl is refused", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return refused(out, code), fmt.Sprintf("exit %d %s", code, out)
	})

	// Attach it again and see the GET work before deleting the object, so a push that never
	// happened cannot make the delete look like deny-all.
	c.apply(silo("example"))
	c.eventually("attached again: GET works", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return allowed(out, code), fmt.Sprintf("exit %d %s", code, out)
	})
	if out, code := c.kvo("", "delete", "openshellpolicy", "example", "-n", ns); code != 0 {
		t.Fatalf("delete the policy: %s", out)
	}
	c.eventually("deleted while attached: deny-all", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return refused(out, code), fmt.Sprintf("exit %d %s", code, out)
	})
}
