//go:build metal

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
)

// letsEncryptStaging is the only ACME directory a test may use: certificates from it are
// untrusted by design and its rate limits are meant for tests. Never production.
const letsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

// TestMetalIngress is ingress through a stock nginx (design §7.3, ADR 0008) on a real external
// IP: kvoadm ingress install puts the vendor's image in a silo with hostPort: [external]; an
// Ingress to a silo's service with tls: none answers this Mac on port 80, and one with no tls:
// block (HTTPS, the default) redirects port 80 there; an Ingress with a broken annotation is
// refused (or holds the class at its last good config) while traffic keeps flowing; and, only
// when KEVASO_METAL_HOSTNAME names the machine in public DNS, a certificate from Let's Encrypt's
// STAGING directory over HTTP-01, served on 443.
//
// Listens on the external IP while it runs: 80 and 443 (the nginx silo).
func TestMetalIngress(t *testing.T) {
	c := metal(t)
	ns := "web"
	extra := []string{"ingress/site", "ingress/tlsdefault", "ingress/broken", "ingress/secure", "issuer//le-staging"}
	c.namespace(ns, extra...)
	t.Cleanup(func() {
		for _, a := range [][]string{{"delete", "ingressclass", "public"}, {"delete", "silo", "ingress-public", "-n", "kevaso-system"}} {
			if o, code := c.kvo("", a...); code != 0 {
				t.Logf("cleanup: %s", strings.TrimSpace(o))
			}
		}
	})
	var o strings.Builder
	if code := kvoadm.Run(c.ctx, []string{"ingress", "install", "--host-port", "external", "--context", metalCluster}, strings.NewReader(""), &o, &o); code != 0 {
		t.Fatalf("kvoadm ingress install: exit %d\n%s", code, o.String())
	}
	t.Logf("kvoadm ingress install:\n%s", o.String())
	name := "site." + strings.ReplaceAll(c.cfg.ExternalIP, ".", "-") + ".sslip.io" // a name; the test sends it as Host, no DNS needed
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
  tls: { none: true }   # plain HTTP: allowed on a class that isn't public (kvoadm ingress install without --public)
  rules: [{ path: /, service: { name: app, port: http } }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: tlsdefault, namespace: ` + ns + ` }
spec:
  ingressClass: public
  hosts: [tls.` + name + `]
  rules: [{ path: /, service: { name: app, port: http } }]
`)
	c.waitRunning("kevaso-system", 10*time.Minute, "ingress-public")
	c.waitRunning(ns, 10*time.Minute, "app")
	get := func() (bool, string) {
		code, body, err := fromMac("http://"+c.cfg.ExternalIP+"/", name, 5*time.Second)
		return err == nil && code == 200 && strings.Contains(body, "app 8080"), fmt.Sprint(code, " ", strings.TrimSpace(body), " ", err)
	}
	c.eventually("the Ingress answers this Mac on port 80", 3*time.Minute, get)
	// No tls: block means HTTPS (the default): port 80 answers with a redirect to it.
	c.eventually("an Ingress without tls: redirects port 80 to HTTPS", time.Minute, func() (bool, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+c.cfg.ExternalIP+"/x?y=1", nil)
		req.Host = "tls." + name
		resp, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			return false, err.Error()
		}
		_ = resp.Body.Close()
		loc := resp.Header.Get("Location")
		return resp.StatusCode == 308 && loc == "https://tls."+name+"/x?y=1", fmt.Sprint(resp.StatusCode, " ", loc)
	})
	code, _, _ := fromMac("http://"+c.cfg.ExternalIP+"/", "nobody."+name, 5*time.Second)
	if code != 404 {
		t.Errorf("an unknown host: %d, want 404", code)
	}

	// A broken annotation: refused at the door, or held by the proxy's own check with the class
	// kept at its last good config. Either way, traffic doesn't stop.
	out, rc := c.kvo(`apiVersion: kevaso/v1
kind: Ingress
metadata:
  name: broken
  namespace: `+ns+`
  annotations: { nginx/proxy-body-size: "lots; return 500" }
spec:
  ingressClass: public
  hosts: [broken.`+name+`]
  rules: [{ path: /, service: { name: app, port: http } }]
`, "apply", "-f", "-")
	if rc != 0 {
		t.Logf("the broken annotation was refused: %s", strings.TrimSpace(out))
	} else {
		c.eventually("the class names the broken Ingress and keeps its last good config", 2*time.Minute, func() (bool, string) {
			var ic v1.IngressClass
			raw, _ := c.kvo("", "get", "ingressclass", "public", "-o", "json")
			if json.Unmarshal([]byte(raw), &ic) != nil {
				return false, raw
			}
			for _, ctl := range ic.Status.Controllers {
				if ctl.Rejected != "" || strings.Contains(strings.Join(ctl.Blamed, " "), "broken") {
					return true, ""
				}
			}
			return false, raw
		})
	}
	c.holds("traffic keeps flowing", 20*time.Second, get)

	host := c.cfg.Hostname
	if host == "" {
		t.Log("KEVASO_METAL_HOSTNAME isn't set: the Let's Encrypt staging certificate isn't tried")
		return
	}
	email := ""
	if e := os.Getenv("KEVASO_METAL_ACME_EMAIL"); e != "" {
		email = "\n    email: " + e
	}
	// The broken Ingress stays: a held class must still serve the ACME challenges.
	c.apply(`apiVersion: kevaso/v1
kind: Issuer
metadata: { name: le-staging }
spec:
  acme:
    server: ` + letsEncryptStaging + email + `
    solvers: [{ http01: {} }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: secure, namespace: ` + ns + ` }
spec:
  ingressClass: public
  hosts: [` + host + `]
  tls: { issuer: le-staging }
  rules: [{ path: /, service: { name: app, port: http } }]
`)
	c.eventually("a certificate from Let's Encrypt STAGING over HTTP-01", 10*time.Minute, func() (bool, string) {
		out, _ := c.kvo("", "get", "certificate", "secure-tls", "-n", ns)
		return strings.Contains(out, " yes"), out
	})
	c.eventually("443 serves it", 2*time.Minute, func() (bool, string) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", net.JoinHostPort(c.cfg.ExternalIP, "443"),
			&tls.Config{ServerName: host, InsecureSkipVerify: true}) // staging roots are untrusted by design; the issuer is checked instead
		if err != nil {
			return false, err.Error()
		}
		defer func() { _ = conn.Close() }()
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			return false, "no certificate"
		}
		leaf := certs[0]
		ok := strings.Contains(leaf.Issuer.String(), "STAGING") && leaf.VerifyHostname(host) == nil
		return ok, fmt.Sprintf("subject %s, issuer %s", leaf.Subject, leaf.Issuer)
	})
}

// TestMetalProbes is routeWhen on the outside (design §0.6): with routeWhen: ready, the external
// port and the service's name are held until the readiness probe passes, and again when it fails;
// with routeWhen: running, both are there throughout.
//
// Listens on the external IP while it runs: 18110 (gated, while ready), 18111 (always).
func TestMetalProbes(t *testing.T) {
	c := metal(t)
	ns := "probes"
	c.namespace(ns)
	probed := func(name string, port int, when string) string {
		return boxEcho(ns, name, port) + fmt.Sprintf(`  ports: [{ name: web, port: %d }]
  service:
    routeWhen: %s
    ports: [{ port: web, hostPort: [external] }]
  probes:
    readiness: { exec: { command: [test, -f, /tmp/ready] }, period: 2s, successes: 1, failures: 1 }
`, port, when)
	}
	c.apply(probed("gated", 18110, "ready") + "---\n" + probed("always", 18111, "running") + "---\n" + vmEcho(ns, "asker", 8080))
	c.waitRunning(ns, 20*time.Minute, "gated", "always", "asker")
	name := func(svc string) string {
		out, _ := c.in(ns, "asker", "getent ahostsv4 "+svc+"."+ns+"."+c.suffix+" | awk 'NR==1 {print $1}'")
		return strings.TrimSpace(out)
	}
	held := func() (bool, string) {
		ok, got := c.closed(18110)
		return ok && name("gated") == "", got
	}
	routed := func() (bool, string) {
		ok, got := c.open(18110)
		return ok && name("gated") != "", got
	}
	always := func() (bool, string) {
		ok, got := c.open(18111)
		return ok && name("always") != "", got
	}

	c.holds("routeWhen ready, not ready: port and name held", 15*time.Second, held)
	c.holds("routeWhen running, not ready: port and name there", 5*time.Second, always)
	c.in(ns, "gated", "touch /tmp/ready")
	c.eventually("ready: the port opens and the name answers", time.Minute, routed)
	c.in(ns, "gated", "rm -f /tmp/ready")
	c.eventually("not ready again: held again", time.Minute, held)
	c.holds("routeWhen running is never held", 5*time.Second, always)
}
