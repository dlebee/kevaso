//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// pebbleVersion is Let's Encrypt's test ACME server, the stand-in for Let's Encrypt.
const pebbleVersion = "v2.10.3"

func buildPebble(t *testing.T, ctx context.Context, arch string) string {
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pebble: go %v: %v\n%s", args, err, out)
		}
	}
	run("mod", "init", "pebbleget")
	run("get", "github.com/letsencrypt/pebble/v2/cmd/pebble@"+pebbleVersion)
	run("build", "-o", "pebble", "github.com/letsencrypt/pebble/v2/cmd/pebble")
	run("build", "-o", "pebble-challtestsrv", "github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv")
	return dir
}

// TestIngressHTTPS is M10's "done when" (example 04): HTTPS for several private silos through an
// ingress controller silo running stock nginx (design §7.3: its config is rendered by the nginx
// driver and written, checked and reloaded by metal-1's agent from outside), with certificates from an ACME server over real HTTP-01, renewed by
// Kevaso. Pebble stands in for Let's Encrypt on the client machine; names come from sslip.io (public
// DNS: NAME.<ip>.sslip.io resolves to the IP), so the ACME server really fetches the challenge from
// the ingress controller on metal-1's port 80. Some hosts are proven with DNS-01 instead: Pebble
// resolves through pebble-challtestsrv, whose TXT records a DNS provider program registered on
// metal-1's control plane writes (the same way a script against a DNS host's API would).
//
//	metal-1  control plane + worker (docker): the ingress controller and two private apps
//	client   "the internet": Pebble, and the browser
func TestIngressHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	d, arch := driver(t)
	sshd, ok := d.(testbed.SSHAccess)
	if !ok {
		t.Skip("needs a driver with SSH access (Lima)")
	}
	if os.Getenv("LIMA_HOME") == "" {
		real, _ := os.UserHomeDir()
		t.Setenv("LIMA_HOME", filepath.Join(real, ".lima"))
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KVO_CONFIG", filepath.Join(home, ".kevaso", "config.yaml"))
	t.Setenv("KVO_SERVER", "")

	run := testbed.NewRunID()
	specs := map[string]testbed.Spec{
		"metal":  {Role: "metal", CPUs: 4, Memory: "4GiB", Disk: "30GiB", Shared: true},
		"client": {Role: "client", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
	}
	machines := map[string]testbed.Machine{}
	var mu sync.Mutex
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING the run's machines (limactl list | grep %s)", run)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, s := range specs {
			_ = d.Delete(ctx, testbed.Machine{Name: testbed.MachineName(run, s.Role), Run: run, Role: s.Role})
		}
	})
	var wg sync.WaitGroup
	errs := make(chan error, len(specs))
	for name, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := d.Create(ctx, run, s)
			if err != nil {
				errs <- fmt.Errorf("create %s: %w", name, err)
				return
			}
			mu.Lock()
			machines[name] = m
			mu.Unlock()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	sh := func(name, cmd string) (string, error) { return d.Exec(ctx, machines[name], "sudo", "sh", "-c", cmd) }
	addrOf := func(name string) string {
		out, err := sh(name, `ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1`)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	metalIP, clientIP := addrOf("metal"), addrOf("client")
	mzone := strings.ReplaceAll(metalIP, ".", "-") + ".sslip.io"
	czone := strings.ReplaceAll(clientIP, ".", "-") + ".sslip.io"
	apiHost, shopHost, pebbleHost := "api."+mzone, "shop."+mzone, "pebble."+czone
	docsHost, wildHost := "docs."+mzone, "*.wild."+mzone // proven by DNS-01
	t.Logf("metal-1 %s, client %s; sites %s %s; ACME at %s", metalIP, clientIP, apiHost, shopHost, pebbleHost)

	// Pebble on the client, its own API on a certificate from the test's CA, validating HTTP-01
	// on port 80 like Let's Encrypt.
	pebbleDir := buildPebble(t, ctx, arch)
	for _, b := range []string{"pebble", "pebble-challtestsrv"} {
		if err := copyTo(ctx, machines["client"], filepath.Join(pebbleDir, b), "/usr/local/bin/"+b); err != nil {
			t.Fatal(err)
		}
	}
	setup := strings.ReplaceAll(inetSetup, "DNS:api.allowed.test,DNS:pass.test,DNS:other.blocked.test", "DNS:"+pebbleHost)
	caOut, err := sh("client", setup+`
systemctl stop inet
cat > /etc/inet/pebble.json <<JSON
{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/etc/inet/leaf.pem", "privateKey": "/etc/inet/leaf.key",
  "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false}}
JSON
systemd-run --unit=challtestsrv /usr/local/bin/pebble-challtestsrv -defaultIPv4 `+metalIP+` -defaultIPv6 "" \
  -dnsserver 127.0.0.1:8053 -management 0.0.0.0:8055 -http01 "" -https01 "" -tlsalpn01 "" -doh ""
systemd-run --unit=pebble --setenv=PEBBLE_VA_NOSLEEP=1 --setenv=PEBBLE_WFE_NONCEREJECT=0 /usr/local/bin/pebble -config /etc/inet/pebble.json -dnsserver 127.0.0.1:8053
sleep 2
cat /etc/inet/ca.pem`)
	if err != nil {
		t.Fatalf("pebble: %v\n%s", err, caOut)
	}
	inetCA := strings.TrimSpace(caOut[strings.LastIndex(caOut, "-----BEGIN CERTIFICATE-----"):])

	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	type cmd func(context.Context, []string, io.Reader, io.Writer, io.Writer) int
	must := func(f cmd, stdin string, args ...string) string {
		t.Helper()
		var o, e bytes.Buffer
		if code := f(ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, o.String(), e.String())
		}
		return o.String()
	}
	info, err := sshd.SSH(ctx, machines["metal"])
	if err != nil {
		t.Fatal(err)
	}
	// The DNS provider: a program in /etc/kevaso/dns-providers, called present|cleanup FQDN VALUE.
	if out, err := sh("metal", `mkdir -p /etc/kevaso/dns-providers && cat > /etc/kevaso/dns-providers/challtest <<'SH'
#!/bin/sh
set -e
case "$1" in
present) curl -fsS -X POST -d "{\"host\":\"$2\",\"value\":\"$3\"}" http://`+clientIP+`:8055/set-txt ;;
cleanup) curl -fsS -X POST -d "{\"host\":\"$2\"}" http://`+clientIP+`:8055/clear-txt ;;
*) exit 2 ;;
esac
echo "challtest: $1 $2" >&2
SH
chmod 0755 /etc/kevaso/dns-providers/challtest`); err != nil {
		t.Fatalf("dns provider: %v\n%s", err, out)
	}
	hk, _ := d.Exec(ctx, machines["metal"], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	must(kvoadm.Run, "", "init", info.User+"@"+info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", strings.Fields(hk)[1], "--kevasod", bin, "--name", "metal-1", "--cluster", "e2e",
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker", "--runtime", "docker")

	app := func(name, ns, port, page string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %[1]s, namespace: %[2]s }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: [python3, -m, http.server, "%[3]s", --directory, /site] }
  volumes: [{ name: site, mountPath: /site }]
  ports: [{ name: http, port: %[3]s }]
  service:
    ports: [{ port: http }]
  init:
    steps:
      - name: page
        run: echo %[4]s | base64 -d > /site/index.html
`, name, ns, port, base64.StdEncoding.EncodeToString([]byte(page)))
	}
	manifest := `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: kevaso-system }
---
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: payments }
---
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: shop }
---
apiVersion: kevaso/v1
kind: Issuer
metadata: { name: pebble }
spec:
  acme:
    server: https://` + pebbleHost + `:14000/dir
    email: ops@example.com
    serverCA: |
` + indent(inetCA, "      ") + `
    solvers:
      - http01: {}
      - selector: { dnsNames: [` + docsHost + `], dnsZones: [wild.` + mzone + `] }
        dns01: { provider: challtest, propagationSeconds: 2 }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: ingress-public, namespace: kevaso-system }
spec:
  runtime: docker
  container: { image: docker.io/library/nginx:1.27 }   # the vendor's image as shipped: driven from outside
  ports: [{ name: http, port: 80 }, { name: https, port: 443 }]
  service:
    ports: [{ port: http, hostPort: [internal] }, { port: https, hostPort: [internal] }]
---
apiVersion: kevaso/v1
kind: IngressClass
metadata: { name: public }
spec:
  controller: { driver: nginx, silo: ingress-public, namespace: kevaso-system }
  public: true
` + app("api", "payments", "8080", "hello from the api") + app("web", "shop", "3000", "hello from the shop") + `---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: api, namespace: payments }
spec:
  ingressClass: public
  hosts: [` + apiHost + `]
  tls: { issuer: pebble }
  rules: [{ path: /, service: { name: api, port: http } }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: shop, namespace: shop }
spec:
  ingressClass: public
  hosts: [` + shopHost + `]
  tls: { issuer: pebble }
  rules: [{ path: /, service: { name: web, port: http } }]
---
apiVersion: kevaso/v1
kind: Ingress
metadata: { name: docs, namespace: shop }
spec:
  ingressClass: public
  hosts: [` + docsHost + `]
  tls: { issuer: pebble }
  rules: [{ path: /, service: { name: web, port: http } }]
---
apiVersion: kevaso/v1
kind: Certificate
metadata: { name: wild, namespace: shop }
spec:
  hosts: ["` + wildHost + `"]
  issuer: pebble
  secretName: wild-tls
`
	must(kvo.Run, manifest, "apply", "-f", "-")

	deadline := time.Now().Add(25 * time.Minute)
	waited := 0
	for {
		silos, _ := kvoRun(ctx, "", "get", "silos", "-A")
		certs, _ := kvoRun(ctx, "", "get", "certificates", "-A")
		if strings.Count(silos, "Running") == 3 && strings.Count(certs, " yes") == 4 {
			t.Logf("silos:\n%s\ncertificates:\n%s", silos, certs)
			break
		}
		if waited++; waited%12 == 0 {
			t.Logf("still waiting:\n%s\n%s", silos, certs)
		}
		if time.Now().After(deadline) {
			j, _ := sh("metal", "journalctl -u kevasod -n 60 --no-pager | grep -v 'retry in 5m' | tail -40")
			for _, c := range []string{"api-tls -n payments", "shop-tls -n shop", "docs-tls -n shop", "wild -n shop"} {
				desc, _ := kvoRun(ctx, "", append([]string{"describe", "certificate"}, strings.Fields(c)...)...)
				t.Log(desc)
			}
			t.Fatalf("silos:\n%s\ncertificates:\n%s\nkevasod:\n%s", silos, certs, j)
		}
		time.Sleep(10 * time.Second)
	}

	// The browser: trust Pebble's issuing root, and nothing else.
	if _, err := sh("client", "curl -sk https://localhost:15000/roots/0 > /etc/inet/pebble-root.pem && test -s /etc/inet/pebble-root.pem"); err != nil {
		t.Fatal(err)
	}
	expect := func(what, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", what, got, want)
		} else {
			t.Logf("%s: ok", what)
		}
	}
	curl := func(args string) string {
		// Names pinned to metal-1: the test doesn't depend on reaching sslip.io from the client.
		pin := ""
		for _, h := range []string{apiHost, shopHost, docsHost} {
			pin += " --resolve " + h + ":443:" + metalIP + " --resolve " + h + ":80:" + metalIP
		}
		out, _ := sh("client", "curl -sS --max-time 10 --cacert /etc/inet/pebble-root.pem"+pin+" "+args+" 2>&1")
		return strings.TrimSpace(out)
	}
	expect("https://api over a Pebble certificate", curl("https://"+apiHost+"/"), "hello from the api")
	expect("https://shop, another namespace", curl("https://"+shopHost+"/"), "hello from the shop")
	expect("https://docs, its certificate proven by DNS-01", curl("https://"+docsHost+"/"), "hello from the shop")
	txt, _ := sh("client", "journalctl -u challtestsrv --no-pager | grep -ci txt")
	if n, _ := strconv.Atoi(strings.TrimSpace(txt)); n == 0 {
		t.Error("no TXT record was ever written: DNS-01 wasn't used")
	} else {
		t.Logf("DNS-01: %d TXT record changes at the DNS server: ok", n)
	}
	expect("a wildcard certificate (DNS-01 only)", must(kvo.Run, "", "describe", "certificate", "wild", "-n", "shop"), "*.wild.")
	expect("http redirects to https", curl("-o /dev/null -w '%{http_code} %{redirect_url}' http://"+apiHost+"/x"), "308 https://"+apiHost+"/x")
	expect("the certificate is for the host (its SAN)", curl("-v -o /dev/null https://"+apiHost+"/"), "matched cert's \""+apiHost+"\"")
	expect("an unknown host", curl("-o /dev/null -w '%{http_code}' --resolve nobody."+mzone+":80:"+metalIP+" http://nobody."+mzone+"/"), "404")
	if got := curl("-o /dev/null -w '%{http_code}' http://" + metalIP + ":8080/"); strings.Contains(got, "200") {
		t.Errorf("the app's own port answered from outside: %q", got)
	}

	var ing v1.Ingress
	if err := json.Unmarshal([]byte(must(kvo.Run, "", "get", "ingress", "api", "-n", "payments", "-o", "json")), &ing); err != nil {
		t.Fatal(err)
	}
	if ing.Status.Address != metalIP {
		t.Errorf("Ingress address %q, want %s", ing.Status.Address, metalIP)
	}
	t.Logf("kvo get ingresses -A:\n%s", must(kvo.Run, "", "get", "ingresses", "-A"))

	// The proxy is stock nginx, configured from outside: the class says it's applied, and the
	// config in the container is the one the driver rendered (no Kevaso process in it).
	var class v1.IngressClass
	if err := json.Unmarshal([]byte(must(kvo.Run, "", "get", "ingressclass", "public", "-o", "json")), &class); err != nil {
		t.Fatal(err)
	}
	if len(class.Status.Controllers) != 1 || class.Status.Controllers[0].Applied == "" || class.Status.Controllers[0].Rejected != "" {
		t.Errorf("class status %+v", class.Status)
	}
	ps, _ := sh("metal", "docker ps --format '{{.Image}} {{.Names}}' | grep nginx")
	expect("the controller runs the vendor's image", ps, "docker.io/library/nginx:1.27")
	conf, _ := sh("metal", "docker exec $(docker ps -q --filter label=kevaso.com/name=ingress-public | head -1) cat /etc/nginx/nginx.conf")
	expect("its nginx.conf is the driver's", conf, "Rendered by Kevaso's nginx ingress driver")
	top, _ := sh("metal", "docker exec $(docker ps -q --filter label=kevaso.com/name=ingress-public | head -1) sh -c 'cat /proc/[0-9]*/comm' | sort -u")
	if strings.Contains(top, "kvo") || strings.Contains(top, "kevaso") {
		t.Errorf("a Kevaso process in the proxy's container:\n%s", top)
	}

	// A knob nginx doesn't know is refused, and the running config stays.
	must(kvo.Run, `apiVersion: kevaso/v1
kind: Ingress
metadata: { name: api, namespace: payments, annotations: { nginx/no-such-knob: "1" } }
spec:
  ingressClass: public
  hosts: [`+apiHost+`]
  tls: { issuer: pebble }
  rules: [{ path: /, service: { name: api, port: http } }]
`, "apply", "-f", "-")
	time.Sleep(10 * time.Second)
	desc := must(kvo.Run, "", "describe", "ingress", "api", "-n", "payments")
	expect("an unknown annotation shows on the Ingress", desc, "no-such-knob")
	expect("the last good config is still served", curl("https://"+apiHost+"/"), "hello from the api")
}

func indent(s, pre string) string {
	return pre + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n"+pre)
}

// copyTo puts a local file on a machine (as root).
func copyTo(ctx context.Context, m testbed.Machine, local, remote string) error {
	tmp := "/tmp/" + filepath.Base(remote) + ".upload"
	if out, err := exec.CommandContext(ctx, "limactl", "copy", local, m.Name+":"+tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("limactl copy: %v: %s", err, out)
	}
	out, err := exec.CommandContext(ctx, "limactl", "shell", m.Name, "sudo", "install", "-m", "0755", tmp, remote).CombinedOutput()
	if err != nil {
		return fmt.Errorf("install %s: %v: %s", remote, err, out)
	}
	return nil
}
