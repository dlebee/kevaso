//go:build metal

package e2e

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/builtin/kri/openshell"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/sdk/kri"
)

// TestMetalOpenShell is OpenShell on the machine, both drivers (openshell: a VM sandbox;
// openshell-container: a Docker one), added to the worker with kvoadm host enable-worker next to
// cloud-hypervisor and docker, whose silos keep running untouched throughout:
//
//   - both runtimes install on the machine's Ubuntu and get Ready;
//   - a silo of each runs: kvo exec, a terminal of the Mac's size (kvo exec -it), the name it
//     has on its gateway;
//   - what OpenShell can't do is refused at admission with its reason: a service (hostPort:
//     [external]: it has no network card), a file or env delivery, the local endpoint (broker),
//     a registry pull;
//   - a secret by inject: the silo holds OpenShell's placeholder, the stand-in API sees the key,
//     a name no grant allows is refused, the key is nowhere inside;
//   - the gateway stopped behind Kevaso's back: the agent starts the silo again; kvo reset makes
//     it fresh (a file written before is gone); delete leaves nothing of it on its gateway;
//   - the runtimes are taken off again. kvoadm reset at the end of the run covers what they
//     installed (the package, the gateways' units, users and state, the sandboxes' images):
//     its checklist, and TestMetalCheck.
//
// Listens on nothing outside (the service is refused).
func TestMetalOpenShell(t *testing.T) {
	c := metal(t)
	ns := "osh"
	c.namespace(ns, "grant/api", "grant/files", "grant/vars", "grant/broker", "grant/preload", "secret/api-key", "secret/plain", "secret/regcred")

	// Side by side: a microVM and a docker silo, from before the runtimes are added.
	c.apply(vmEcho(ns, "vmside", 8080) + "---\n" + boxEcho(ns, "ctside", 8080))
	c.waitRunning(ns, 20*time.Minute, "vmside", "ctside")
	vm := c.silo(ns, "vmside")
	vmUnit := cloudhypervisor.NamesFor(kri.ID{Namespace: ns, Name: vm.Name, UID: vm.UID}).Unit
	ctUID := c.silo(ns, "ctside").UID
	sides := func() string {
		return strings.TrimSpace(c.mustSh(`docker ps -q --filter label=kevaso.com/uid=`+ctUID+` --filter label=kevaso.com/name | xargs -r docker inspect -f '{{.State.StartedAt}}'`)) + " " +
			strings.TrimSpace(c.mustSh("systemctl show -p ActiveEnterTimestamp,ActiveState --value "+vmUnit))
	}
	before := sides()

	c.enableWorker("cloud-hypervisor", "docker", "openshell", "openshell-container")
	t.Cleanup(func() { c.enableWorker("cloud-hypervisor", "docker") })
	c.runtimeReady("openshell", 25*time.Minute)
	c.runtimeReady("openshell-container", 25*time.Minute)
	c.expect("OpenShell's package is installed", c.mustSh("dpkg-query -W -f '${Status} ${Version}' "+openshell.Package+" 2>&1"), "install ok installed "+strings.TrimPrefix(openshell.Version, "v"))

	// Refused at admission, each with its reason.
	apiKey := randomValue(t, "sk-os-")
	c.must(apiKey, "create", "secret", "api-key", "-n", ns, "--from-file", "-", "--allow", "inject", "--write-only")
	c.must("x", "create", "secret", "plain", "-n", ns, "--from-file", "-")
	c.must("x", "create", "secret", "regcred", "-n", ns, "--type", "registry", "--server", "registry.example", "--username", "u", "--from-file", "-")
	osSilo := func(name, runtime, extra string) string {
		return fmt.Sprintf("---\napiVersion: kevaso/v1\nkind: Silo\nmetadata: { name: %s, namespace: %s }\nspec:\n  runtime: %s\n  container: { image: ubuntu-24.04 }\n  resources: { cpu: 1, memory: 1Gi }\n%s",
			name, ns, runtime, extra)
	}
	grant := func(name, secret string) string {
		return fmt.Sprintf("---\napiVersion: kevaso/v1\nkind: Grant\nmetadata: { name: %s, namespace: %s }\nspec:\n  secrets:\n    - %s\n", name, ns, secret)
	}
	c.apply(grant("files", "{ name: plain, deliver: file, path: /run/secrets/plain }") +
		grant("vars", "{ name: plain, deliver: env, env: PLAIN }") + grant("broker", "{ name: plain, deliver: broker }") +
		grant("preload", "{ name: api-key, deliver: inject, env: LD_PRELOAD, to: { host: "+osInetName+" } }"))
	for _, rt := range []string{"openshell", "openshell-container"} {
		for what, c2 := range map[string]struct{ extra, want string }{
			"a service (hostPort: [external])":  {"  ports: [{ name: web, port: 18150 }]\n  service:\n    ports: [{ port: web, hostPort: [external] }]\n", "no network interface, so no service"},
			"a file delivery":                   {"  grants: [files]\n", "can't put a file or a variable in an OpenShell sandbox"},
			"an env delivery":                   {"  grants: [vars]\n", "can't put a file or a variable in an OpenShell sandbox"},
			"the local endpoint (broker)":       {"  grants: [broker]\n", "can't reach the host's local endpoint"},
			"a registry pull":                   {"", "OpenShell pulls images through its own gateway"},
			"an inject into LD_PRELOAD (K-066)": {"  grants: [preload]\n", "LD_* variables steer"},
		} {
			m := osSilo("refused", rt, c2.extra)
			if what == "a registry pull" {
				m = strings.Replace(m, "container: { image: ubuntu-24.04 }", "container: { image: registry.example/x:1, pull: { secretRef: regcred } }", 1)
			}
			out, code := c.kvo(m, "apply", "-f", "-")
			if code == 0 {
				t.Errorf("%s: %s accepted", rt, what)
				_, _ = c.kvo("", "delete", "silo", "refused", "-n", ns)
				continue
			}
			c.expect(rt+": "+what+" refused, saying why", out, c2.want)
		}
	}

	// A silo of each, with a key by inject. A sandbox resolves names through OpenShell's own DNS,
	// not the host's /etc/hosts: the stand-in API gets a public name (sslip.io, for an address on
	// the machine's loopback that only its gateway's proxy reaches), with a certificate from the
	// stand-in internet's CA.
	c.mustSh(osInetSetup)
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: api, namespace: ` + ns + ` }
spec:
  secrets:
    - { name: api-key, deliver: inject, env: API_KEY, to: { host: ` + osInetName + ` } }
` + osSilo("osvm", "openshell", "  grants: [api]\n") + osSilo("osct", "openshell-container", "  grants: [api]\n"))
	c.waitRunning(ns, 35*time.Minute, "osvm", "osct")

	hget := buildHget(t, c.arch)
	kvoBin := buildKvo(t)
	for _, s := range []string{"osvm", "osct"} {
		t.Run(s, func(t *testing.T) {
			c := c.with(t)
			c.expect("kvo exec", func() string { o, _ := c.in(ns, s, "echo exec-ok"); return o }(), "exec-ok")
			// A terminal of the Mac's size, its exit code.
			p := startPty(t, c.ctx, kvoBin, 29, 97, "exec", "-it", "silo", s, "-n", ns, "--", "sh", "-c", `echo "tty=$(tty) size=$(stty size)"; exit 5`)
			p.waitFor("kvo exec -it: a terminal of the Mac's size", regexp.MustCompile(`tty=/dev/pts/\d+ size=29 97`), 2*time.Minute)
			if code := p.exit(time.Minute); code != 5 {
				t.Errorf("kvo exec -it exit code %d, want 5", code)
			}
			// Its name on its gateway.
			id := kri.ID{Namespace: ns, Name: s, UID: c.silo(ns, s).UID}
			name := openshell.SandboxName(id)
			if s == "osct" {
				c.expect("the Docker sandbox is named for the silo", c.mustSh("docker ps --format '{{.Names}}'"), name)
			}
			t.Logf("its hostname inside: %s; its sandbox: %s", func() string { o, _ := c.in(ns, s, "hostname"); return o }(), name)

			// The key by inject (OpenShell takes at most 4 MiB of piped stdin: the client compressed).
			var o bytes.Buffer
			if code := kvo.Run(c.ctx, []string{"exec", "silo", s, "-n", ns, "--", "sh", "-c", "gunzip -c > /sandbox/hget && chmod +x /sandbox/hget"}, bytes.NewReader(hget), &o, &o); code != 0 {
				t.Fatalf("upload hget: %d %s", code, o.String())
			}
			env, _ := c.in(ns, s, "echo $API_KEY")
			if !strings.HasPrefix(env, "openshell:resolve:env:") || strings.Contains(env, apiKey) {
				t.Fatalf("API_KEY in the silo is %q, want OpenShell's placeholder", env)
			}
			got, _ := c.in(ns, s, `/sandbox/hget https://`+osInetName+`/v1/models "Authorization=Bearer $API_KEY"`)
			c.expect("the placeholder became the key on the way out", got, `"auth": "`+metalHash("Bearer "+apiKey)+`"`)
			if got, _ := c.in(ns, s, `/sandbox/hget https://example.com/`); strings.HasPrefix(got, "200") {
				t.Errorf("a name no grant allows answered: %q", got)
			} else {
				t.Logf("a name no grant allows: refused (%s)", firstLineOf(got))
			}
			if n, _ := c.in(ns, s, fmt.Sprintf("grep -rl -F -e '%s' /sandbox /tmp 2>/dev/null | wc -l; env | grep -c -F -e '%s'", apiKey, apiKey)); strings.Join(strings.Fields(n), " ") != "0 0" {
				t.Errorf("the key is inside the silo: %q", n)
			}

			// Its gateway stopped behind Kevaso's back: the silo is started again.
			c.upload(ns, s, "/sandbox/marker", "before-reset")
			driver := map[string]string{"osvm": openshell.DriverVM, "osct": openshell.DriverDocker}[s]
			gw := openshell.Gateway{Key: openshell.GatewayKey(driver, openshell.ScopeNamespace, id)}.Unit()
			c.expect("its gateway runs", c.mustSh("systemctl is-active "+gw+" || true"), "active")
			c.mustSh("systemctl stop " + gw)
			c.eventually("the gateway stopped: the agent starts it and the silo again", 10*time.Minute, func() (bool, string) {
				active, _ := c.sh("systemctl is-active " + gw)
				out, code := c.in(ns, s, "echo back")
				return strings.TrimSpace(active) == "active" && code == 0 && out == "back", strings.TrimSpace(active) + " " + out
			})
			// kvo reset: fresh, the file is gone.
			c.must("", "reset", "silo", s, "-n", ns)
			c.eventually("kvo reset: a fresh sandbox", 10*time.Minute, func() (bool, string) {
				out, code := c.in(ns, s, "cat /sandbox/marker 2>/dev/null || echo gone")
				return code == 0 && out == "gone", out
			})
		})
	}
	if after := sides(); after != before {
		t.Errorf("the docker and microVM silos restarted while OpenShell came and went: %q → %q", before, after)
	} else {
		t.Log("the docker and microVM silos kept running throughout")
	}

	// Delete: nothing of them left on their gateways.
	ct := openshell.SandboxName(kri.ID{Namespace: ns, Name: "osct", UID: c.silo(ns, "osct").UID})
	for _, s := range []string{"osvm", "osct"} {
		c.must("", "delete", "silo", s, "-n", ns)
	}
	c.eventually("deleted: the Docker sandbox is gone", 5*time.Minute, func() (bool, string) {
		out := c.mustSh("docker ps -a --format '{{.Names}}'")
		return !strings.Contains(out, ct), out
	})
	t.Logf("on the host after the deletes:\n%s", c.mustSh(`systemctl list-units --plain --no-legend 'kevaso-openshell-*'; ls /var/lib/kevaso-openshell/gw 2>&1; docker images --format '{{.Repository}}:{{.Tag}}' | grep -iv python | head`))
}

// osInetName is the stand-in API for OpenShell's sandboxes: a public name for 127.0.0.78.
const osInetName = "kvt-inject.127-0-0-78.sslip.io"

// osInetSetup serves osInetName on 127.0.0.78:443 like metalInetSetup's server (the same CA,
// which the egress gate trusts), as a transient unit the reset stops (kvt-inet-os).
const osInetSetup = `set -e; cd /var/lib/kvt-inet
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout os.key -out os.csr -subj /CN=` + osInetName + ` 2>/dev/null
printf 'subjectAltName=DNS:` + osInetName + `\n' > os.ext
openssl x509 -req -in os.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile os.ext -out os.pem 2>/dev/null
sed -e 's#/var/lib/kvt-inet/leaf.pem#/var/lib/kvt-inet/os.pem#' -e 's#/var/lib/kvt-inet/leaf.key#/var/lib/kvt-inet/os.key#' -e 's#"127.0.0.77"#"127.0.0.78"#' server.py > os-server.py
systemctl stop kvt-inet-os 2>/dev/null || true
systemd-run --unit=kvt-inet-os python3 /var/lib/kvt-inet/os-server.py >/dev/null
`

// buildHget builds the tiny HTTP client for the sandboxes (OpenShell's image has no curl), gzipped.
func buildHget(t *testing.T, arch string) []byte {
	t.Helper()
	dir := t.TempDir()
	src, bin := filepath.Join(dir, "hget.go"), filepath.Join(dir, "hget")
	if err := os.WriteFile(src, []byte(hgetGo), 0o644); err != nil {
		t.Fatal(err)
	}
	b := exec.Command("go", "build", "-ldflags", "-s -w", "-o", bin, src)
	b.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := b.CombinedOutput(); err != nil {
		t.Fatalf("build hget: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return gz.Bytes()
}

func firstLineOf(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// with is the suite's cluster reporting to a subtest.
func (c *mt) with(t *testing.T) *mt {
	d := *c
	d.t = t
	return &d
}
