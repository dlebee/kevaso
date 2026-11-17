//go:build metal

package e2e

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvo"
)

// TestLabOpenShellPolicy is an OpenShellPolicy on a pair lab, the same env file as
// TestMetalOpenShell. The ubuntu image has no curl or python, so the sandbox uses the same
// static client that test copies in. A read-only GET of https://example.com/ is allowed. A POST
// and a path the rule does not name are the proxy's own HTTP response: CONNECT succeeded, and
// the status is 403 with a policy_denied body. Detaching the policy (the silo's list), and
// deleting it while the silo still lists it, is deny-all: the proxy rejects CONNECT, which the
// client reports as a connection error.
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
	c.waitRunning(ns, 35*time.Minute, "box")

	// OpenShell takes at most 4 MiB of piped stdin: the client is compressed, as in
	// TestMetalOpenShell.
	hget := buildHget(t, c.arch)
	var o bytes.Buffer
	if code := kvo.Run(c.ctx, []string{"exec", "silo", "box", "-n", ns, "--", "sh", "-c", "gunzip -c > /sandbox/hget && chmod +x /sandbox/hget"}, bytes.NewReader(hget), &o, &o); code != 0 {
		t.Fatalf("upload hget: %d %s", code, o.String())
	}

	get := `/sandbox/hget https://example.com/`
	post := `/sandbox/hget POST https://example.com/`
	other := `/sandbox/hget https://example.com/not-allowed`
	allowed := func(out string, code int) bool {
		return code == 0 && strings.HasPrefix(out, "200") && strings.Contains(out, "Example Domain")
	}
	// The host is allowed, so the proxy accepts CONNECT and answers the request: HTTP 403,
	// body policy_denied. hget prints that status and exits 0.
	proxyDenied := func(out string, code int) bool {
		return code == 0 && strings.HasPrefix(out, "403") && strings.Contains(out, "policy_denied") && !strings.Contains(out, "Example Domain")
	}
	// Deny-all rejects CONNECT. hget exits with "error: … Forbidden", the status text Go keeps
	// from the proxy's 403, and there is no policy_denied body.
	connectDenied := func(out string, code int) bool {
		return code != 0 && strings.HasPrefix(out, "error:") && strings.Contains(out, "Forbidden") && !strings.Contains(out, "policy_denied") && !strings.Contains(out, "Example Domain")
	}
	c.eventually("GET https://example.com/ is allowed", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return allowed(out, code), fmt.Sprintf("exit %d %s", code, out)
	})
	if out, code := c.in(ns, "box", post); !proxyDenied(out, code) {
		t.Fatalf("POST was not refused by the proxy: exit %d %s", code, out)
	}
	if out, code := c.in(ns, "box", other); !proxyDenied(out, code) {
		t.Fatalf("a path the rule does not allow was not refused: exit %d %s", code, out)
	}

	c.apply(silo(""))
	c.eventually("detached: the GET is refused", 2*time.Minute, func() (bool, string) {
		out, code := c.in(ns, "box", get)
		return connectDenied(out, code), fmt.Sprintf("exit %d %s", code, out)
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
		return connectDenied(out, code), fmt.Sprintf("exit %d %s", code, out)
	})
}
