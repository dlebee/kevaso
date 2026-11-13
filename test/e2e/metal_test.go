//go:build metal

// The metal suite: end-to-end tests on ONE dedicated machine that already exists (bare metal,
// KVM, a real external IP), reached over SSH with a pinned host key (testbed/remote). It is the
// first environment with both microVMs and an address the internet reaches, so it proves what
// Lima (no real external IP) and Linode (no KVM) can't. Build tag metal, so it never runs by
// accident; without the machine's environment variables every test skips and says which are
// missing. The runbook is METAL.md.
//
// One cluster on the machine (control plane and worker in one, cloud-hypervisor and docker),
// made once by the first test that needs it: the machine is reset to clean first (its checklist
// must pass), then kvoadm init. Each test makes its own namespace and removes it when it ends;
// the suite's last step (TestMain) is the reset again, and its checklist.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	"kevaso.com/core/testbed/remote"
)

// The suite's fixed names.
const (
	metalHost    = "metal-1" // the Host's name
	metalCluster = "metal"   // the kvo context
	// metalLoop is the loop file backing the volume group: the machine's disks are left alone.
	metalLoop = "60G"
	// metalInetName is the stand-in for an API on the internet the egress gate injects a key
	// into: an HTTPS server on the machine's loopback (metalInetAddr), with a CA of the test's.
	metalInetName = "api.kvt-inject.test"
	metalInetAddr = "127.0.0.77"
	// testNet is TEST-NET-1 (RFC 5737): a source range nobody connects from.
	testNet = "192.0.2.0/24"
)

// metalSuite is the one cluster, shared by every test of a run.
type metalSuite struct {
	cfg    remote.Config
	d      *remote.Driver
	arch   string // GOARCH of the machine
	uname  string // uname -m of the machine
	macIP  string // this Mac's address as the machine sees it (its SSH client address)
	suffix string // the cluster's DNS suffix
	home   string
}

var metalState struct {
	once    sync.Once
	s       *metalSuite
	err     error
	skip    string
	touched bool           // the machine was reached: the final reset runs
	d       *remote.Driver // set with touched, so the reset runs even when setup failed
}

func TestMain(m *testing.M) {
	code := m.Run()
	if metalState.touched {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			fmt.Println("metal: KEEPING the cluster (KEVASO_E2E_KEEP): reset it later with go test -tags metal -run TestMetalReset")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			err := metalState.d.Reset(ctx)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "metal: the final reset failed:\n%v\n", err)
				code = 1
			} else {
				fmt.Println("metal: the final reset passed its checklist: the machine is clean")
			}
		}
		_ = metalState.d.Close()
	}
	os.Exit(code)
}

// mt is the suite reporting to one test.
type mt struct {
	*metalSuite
	t   *testing.T
	ctx context.Context
}

// metal returns the cluster, making it on first use; it skips the test when the machine isn't
// configured and fails it when making the cluster failed.
func metal(t *testing.T) *mt {
	t.Helper()
	metalState.once.Do(func() { metalState.s, metalState.skip, metalState.err = setUpMetal() })
	if metalState.skip != "" {
		t.Skip(metalState.skip)
	}
	if metalState.err != nil {
		t.Fatalf("the metal cluster: %v", metalState.err)
	}
	return &mt{metalSuite: metalState.s, t: t, ctx: context.Background()}
}

// metalDriver only connects (for TestMetalReset): no cluster.
func metalDriver(t *testing.T) *remote.Driver {
	cfg, err := remote.FromEnv(os.Getenv)
	if errors.Is(err, remote.ErrNotConfigured) {
		t.Skip(err.Error())
	}
	if err != nil {
		t.Fatal(err)
	}
	return remote.New(cfg)
}

func setUpMetal() (s *metalSuite, skip string, err error) {
	cfg, err := remote.FromEnv(os.Getenv)
	if errors.Is(err, remote.ErrNotConfigured) {
		return nil, err.Error(), nil
	}
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	say := func(f string, a ...any) { fmt.Printf("metal: "+f+"\n", a...) }
	s = &metalSuite{cfg: cfg, d: remote.New(cfg)}

	// 1. The machine, its host key checked against the pin before anything is sent.
	out, err := s.d.Run(ctx, `echo "uname=$(uname -m)"; test -c /dev/kvm && echo kvm=yes; ip -4 -o addr show | awk '{print "addr=" $4}'`, nil)
	if err != nil {
		return nil, "", fmt.Errorf("reaching %s: %w", cfg.SSHTarget(), err)
	}
	metalState.touched, metalState.d = true, s.d
	facts := map[string][]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && v != "" {
			facts[k] = append(facts[k], v)
		}
	}
	first := func(k string) string {
		if len(facts[k]) == 0 {
			return ""
		}
		return facts[k][0]
	}
	s.uname = first("uname")
	// This Mac's address as the machine sees it: from the login's own environment (sudo drops
	// SSH_CLIENT), or KEVASO_METAL_MY_IP.
	if who, err := s.d.RunAsLogin(ctx, `echo "${SSH_CLIENT%% *}"`); err == nil {
		s.macIP = strings.TrimSpace(who)
	}
	if ip := os.Getenv("KEVASO_METAL_MY_IP"); ip != "" {
		s.macIP = ip
	}
	if net.ParseIP(s.macIP) == nil {
		return nil, "", fmt.Errorf("this Mac's address as the machine sees it: %q (set KEVASO_METAL_MY_IP)", s.macIP)
	}
	switch s.uname {
	case "x86_64":
		s.arch = "amd64"
	case "aarch64":
		s.arch = "arm64"
	default:
		return nil, "", fmt.Errorf("unsupported CPU %s", s.uname)
	}
	if first("kvm") != "yes" {
		return nil, "", errors.New("the machine has no /dev/kvm: KVM must be on (and nested virtualization isn't the point here)")
	}
	// The DNAT for [external] ports matches the external IP: it must be on an interface (a 1:1
	// NAT cloud address isn't, and nothing would ever match).
	for _, ip := range []string{cfg.ExternalIP, cfg.InternalIP} {
		if ip != "" && !strings.Contains(strings.Join(facts["addr"], " ")+" ", ip+"/") {
			return nil, "", fmt.Errorf("%s isn't on any interface of the machine (ip -4 addr): behind 1:1 NAT, [external] ports can't work", ip)
		}
	}
	say("machine %s (%s), this Mac seen as %s", cfg.SSHTarget(), s.uname, s.macIP)

	// 2. Clean: the baseline (recorded once, on the fresh machine), then a reset to it.
	if _, err := s.d.RecordBaseline(ctx); err != nil {
		return nil, "", err
	}
	if err := s.d.Reset(ctx); err != nil {
		return nil, "", fmt.Errorf("the starting reset: %w", err)
	}
	say("reset to clean: the checklist passed")

	// 3. kevasod for its CPU (built before HOME moves, so the build cache is the usual one).
	tmp, err := os.MkdirTemp("", "kvt-metal-")
	if err != nil {
		return nil, "", err
	}
	bin := filepath.Join(tmp, "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+s.arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("build kevasod: %v\n%s", err, b)
	}
	s.home = filepath.Join(tmp, "home")
	for k, v := range map[string]string{"HOME": s.home, "KVO_CONFIG": filepath.Join(s.home, ".kevaso", "config.yaml"),
		"KVO_TOKEN_STORE": "file", "KVO_SERVER": ""} {
		if err := os.Setenv(k, v); err != nil {
			return nil, "", err
		}
	}

	// 4. The stand-in API on the internet for the injection test, on the machine's loopback,
	// trusted by the egress gate through --egress-extra-ca.
	if out, err := s.d.Run(ctx, metalInetSetup, nil); err != nil {
		return nil, "", fmt.Errorf("the stand-in internet: %v\n%s", err, out)
	}

	// 5. The cluster: one machine, control plane and worker, both runtimes, its addresses declared.
	args := []string{"init", cfg.SSHTarget(), "--ssh-port", strconv.Itoa(cfg.Port), "--ssh-key", cfg.KeyFile, "--host-key", cfg.HostKey,
		"--kevasod", bin, "--name", metalHost, "--cluster", metalCluster, "--api-server", "https://" + net.JoinHostPort(cfg.ExternalIP, "6443"),
		"--external-ip", cfg.ExternalIP, "--worker", "--runtime", "cloud-hypervisor", "--runtime", "docker",
		"--loop-storage", metalLoop, "--egress-extra-ca", "/etc/kevaso/test-internet-ca.pem", "--no-extra-hardening"}
	if cfg.InternalIP != "" {
		args = append(args, "--internal-ip", cfg.InternalIP)
	}
	var o bytes.Buffer
	if code := kvoadm.Run(ctx, args, strings.NewReader(""), &o, &o); code != 0 {
		return nil, "", fmt.Errorf("kvoadm init: exit %d\n%s", code, metalRedact(o.String()))
	}
	say("kvoadm init: %s is Ready (kvo config: KVO_CONFIG=%s)", metalHost, os.Getenv("KVO_CONFIG"))

	// 6. Both runtimes installed (the first silo shouldn't wait on apt).
	deadline := time.Now().Add(20 * time.Minute)
	for {
		var h v1.Host
		var ko bytes.Buffer
		if kvo.Run(ctx, []string{"get", "host", metalHost, "-o", "json"}, nil, &ko, &ko) == 0 && json.Unmarshal(ko.Bytes(), &h) == nil {
			ready := 0
			for _, rt := range []string{"cloud-hypervisor", "docker"} {
				if st, ok := h.Status.Runtimes[rt]; ok && st.State == "Ready" {
					ready++
				} else if ok && st.State == "Failed" {
					return nil, "", fmt.Errorf("runtime %s failed: %s", rt, st.Message)
				}
			}
			if ready == 2 {
				s.suffix = v1.ClusterSuffix([]*v1.Host{&h})
				break
			}
		}
		if time.Now().After(deadline) {
			j, _ := s.d.Run(ctx, "journalctl -u kevasod -n 60 --no-pager", nil)
			return nil, "", fmt.Errorf("the runtimes never got Ready:\n%s\n%s", ko.String(), j)
		}
		time.Sleep(10 * time.Second)
	}
	say("runtimes Ready; names under .%s", s.suffix)
	return s, "", nil
}

// metalRedact keeps the recovery key kvoadm init prints out of the test log.
func metalRedact(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "KVR1-") {
			l = "    (recovery key redacted)"
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// metalInetSetup makes the stand-in internet: a CA, a certificate for metalInetName, and an HTTPS
// server on metalInetAddr:443 that answers with a SHA-256 prefix of the Authorization header it
// got (never the value), run as a transient unit the reset stops (kvt-inet).
const metalInetSetup = `set -e
mkdir -p /etc/kevaso /var/lib/kvt-inet && cd /var/lib/kvt-inet
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 -subj /CN=kvt-internet-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key -out leaf.csr -subj /CN=` + metalInetName + ` 2>/dev/null
printf 'subjectAltName=DNS:` + metalInetName + `\n' > ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out leaf.pem 2>/dev/null
cp ca.pem /etc/kevaso/test-internet-ca.pem
cat > server.py <<'PY'
import ssl, hashlib, json, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        a = self.headers.get("Authorization")
        body = json.dumps({"host": self.headers.get("Host"), "auth": hashlib.sha256(a.encode()).hexdigest()[:16] if a else "none"}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/var/lib/kvt-inet/leaf.pem", "/var/lib/kvt-inet/leaf.key")
s = http.server.ThreadingHTTPServer(("` + metalInetAddr + `", 443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
systemctl stop kvt-inet 2>/dev/null || true
systemd-run --unit=kvt-inet python3 /var/lib/kvt-inet/server.py
sed -i '/` + remote.HostsMarker + `$/d' /etc/hosts
printf '%s %s %s\n' ` + metalInetAddr + ` ` + metalInetName + ` '` + remote.HostsMarker + `' >> /etc/hosts
`

// --- helpers -----------------------------------------------------------------------------------

// sh runs a root script on the machine.
func (c *mt) sh(script string) (string, error) { return c.d.Run(c.ctx, script, nil) }

func (c *mt) mustSh(script string) string {
	c.t.Helper()
	out, err := c.sh(script)
	if err != nil {
		c.t.Fatalf("on the machine: %v\n%s", err, out)
	}
	return out
}

// kvo runs kvo and returns its combined output and exit code.
func (c *mt) kvo(stdin string, args ...string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(c.ctx, args, strings.NewReader(stdin), &o, &o)
	return o.String(), code
}

// must runs kvo and fails the test unless it exits 0.
func (c *mt) must(stdin string, args ...string) string {
	c.t.Helper()
	out, code := c.kvo(stdin, args...)
	if code != 0 {
		c.t.Fatalf("kvo %v: exit %d\n%s", args, code, out)
	}
	return out
}

func (c *mt) apply(manifest string) { c.t.Helper(); c.must(manifest, "apply", "-f", "-") }

// in runs a script inside a silo.
func (c *mt) in(ns, silo, script string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(c.ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", script}, nil, &o, &o)
	return strings.TrimSpace(o.String()), code
}

// upload writes a file into a silo through exec's stdin (no size limit of a command line).
func (c *mt) upload(ns, silo, path, data string) {
	c.t.Helper()
	var o bytes.Buffer
	if code := kvo.Run(c.ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", "mkdir -p \"$(dirname " + path + ")\" && cat > " + path},
		strings.NewReader(data), &o, &o); code != 0 {
		c.t.Fatalf("upload %s to %s: exit %d %s", path, silo, code, o.String())
	}
}

func (c *mt) silo(ns, name string) *v1.Silo {
	c.t.Helper()
	var s v1.Silo
	if err := json.Unmarshal([]byte(c.must("", "get", "silo", name, "-n", ns, "-o", "json")), &s); err != nil {
		c.t.Fatal(err)
	}
	return &s
}

func (c *mt) host() *v1.Host {
	c.t.Helper()
	var h v1.Host
	if err := json.Unmarshal([]byte(c.must("", "get", "host", metalHost, "-o", "json")), &h); err != nil {
		c.t.Fatal(err)
	}
	return &h
}

func (c *mt) journal(lines int) string {
	j, _ := c.sh(fmt.Sprintf("journalctl -u kevasod -n %d --no-pager | grep -v 'retry in' | tail -%d", lines*2, lines))
	return j
}

// waitRunning waits until the silos are Running; it fails with what it knows otherwise.
func (c *mt) waitRunning(ns string, within time.Duration, silos ...string) {
	c.t.Helper()
	deadline := time.Now().Add(within)
	for i := 1; ; i++ {
		out, code := c.kvo("", "get", "silos", "-n", ns, "-o", "json")
		running, failed := 0, ""
		if code == 0 {
			for _, s := range metalSilos(out) {
				for _, want := range silos {
					if s.Name == want && s.Status.Phase == "Running" {
						running++
					} else if s.Name == want && s.Status.Phase == "Failed" {
						failed = s.Name
					}
				}
			}
		}
		if running == len(silos) {
			return
		}
		if time.Now().After(deadline) || failed != "" {
			table, _ := c.kvo("", "get", "silos", "-n", ns)
			for _, s := range silos {
				desc, _ := c.kvo("", "describe", "silo", s, "-n", ns)
				c.t.Log(desc)
			}
			c.t.Fatalf("silos never all Running (%v):\n%s\nkevasod:\n%s", silos, table, c.journal(60))
		}
		if i%12 == 0 {
			table, _ := c.kvo("", "get", "silos", "-n", ns)
			c.t.Logf("still waiting:\n%s", table)
		}
		time.Sleep(5 * time.Second)
	}
}

// eventually polls f every second until it says yes; false (and an error) after within.
func (c *mt) eventually(what string, within time.Duration, f func() (bool, string)) bool {
	c.t.Helper()
	start, last := time.Now(), ""
	for time.Since(start) < within {
		ok, got := f()
		if ok {
			c.t.Logf("%s: ok after %s", what, time.Since(start).Round(time.Second))
			return true
		}
		last = got
		time.Sleep(time.Second)
	}
	c.t.Errorf("%s: not within %s; last: %s", what, within, last)
	return false
}

// holds checks f stays yes for the whole of d (sampled every second).
func (c *mt) holds(what string, d time.Duration, f func() (bool, string)) bool {
	c.t.Helper()
	start := time.Now()
	for time.Since(start) < d {
		if ok, got := f(); !ok {
			c.t.Errorf("%s: stopped holding after %s: %s", what, time.Since(start).Round(time.Second), got)
			return false
		}
		time.Sleep(time.Second)
	}
	c.t.Logf("%s: held for %s", what, d)
	return true
}

func (c *mt) expect(what, got, want string) bool {
	c.t.Helper()
	if !strings.Contains(got, want) {
		c.t.Errorf("%s: got %q, want %q", what, got, want)
		return false
	}
	c.t.Logf("%s: ok", what)
	return true
}

// namespace makes a namespace for one test and removes it, and what's in it, when the test ends:
// its silos first (waiting until they're gone), then the extra objects (KIND/NAME, in the
// namespace; cluster-scoped ones as KIND//NAME), then the namespace.
func (c *mt) namespace(ns string, extra ...string) {
	c.t.Helper()
	c.apply("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: " + ns + " }\n")
	c.t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			c.t.Logf("KEEPING namespace %s", ns)
			return
		}
		out, _ := c.kvo("", "get", "silos", "-n", ns, "-o", "json")
		for _, s := range metalSilos(out) {
			if o, code := c.kvo("", "delete", "silo", s.Name, "-n", ns); code != 0 {
				c.t.Logf("cleanup: %s", o)
			}
		}
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			out, code := c.kvo("", "get", "silos", "-n", ns, "-o", "json")
			if code == 0 && len(metalSilos(out)) == 0 {
				break
			}
			time.Sleep(3 * time.Second)
		}
		for _, e := range extra {
			kind, name, _ := strings.Cut(e, "/")
			args := []string{"delete", kind, name, "-n", ns}
			if strings.HasPrefix(name, "/") {
				args = []string{"delete", kind, strings.TrimPrefix(name, "/")}
			}
			if o, code := c.kvo("", args...); code != 0 {
				c.t.Logf("cleanup %s: %s", e, strings.TrimSpace(o))
			}
		}
		if o, code := c.kvo("", "delete", "namespace", ns); code != 0 {
			c.t.Logf("cleanup namespace %s: %s", ns, strings.TrimSpace(o))
		}
	})
}

// fromMac is an HTTP GET from this Mac (no proxy, redirects not followed), with Host set when
// host isn't empty.
func fromMac(url, host string, timeout time.Duration) (int, string, error) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		// A redirect is an answer to check, not one to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), err
}

// open says whether this Mac gets an HTTP answer on the external IP's port.
func (c *mt) open(port int) (bool, string) {
	code, body, err := fromMac(fmt.Sprintf("http://%s:%d/", c.cfg.ExternalIP, port), "", 5*time.Second)
	if err != nil {
		return false, err.Error()
	}
	return code == 200, fmt.Sprintf("%d %s", code, strings.TrimSpace(body))
}

// closed says whether this Mac gets nothing on the external IP's port.
func (c *mt) closed(port int) (bool, string) {
	ok, got := c.open(port)
	return !ok, got
}

// metalEchoServer is the silos' own software in these tests: answers "NAME PORT" on every port it is
// given (python3: in the Ubuntu image and in python:3.12-slim).
const metalEchoServer = `import http.server as h, threading as t, sys
class H(h.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: a held connection stays usable (the lease test)
    def do_GET(s):
        b = ("%s %d\n" % (sys.argv[1], s.server.server_port)).encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
for p in sys.argv[2:]:
    t.Thread(target=h.ThreadingHTTPServer(("", int(p)), H).serve_forever).start()
`

// echoArgv is the argv that runs metalEchoServer.
func echoArgv(name string, ports ...int) []string {
	argv := []string{"python3", "-c", "exec(__import__('base64').b64decode('" + base64.StdEncoding.EncodeToString([]byte(metalEchoServer)) + "'))", name}
	for _, p := range ports {
		argv = append(argv, strconv.Itoa(p))
	}
	return argv
}

// yamlStr is s as a YAML scalar (JSON's quoting is YAML's).
func yamlStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// yamlList is a flow sequence of strings.
func yamlList(ss []string) string { b, _ := json.Marshal(ss); return string(b) }

// vmEcho is a cloud-hypervisor silo running metalEchoServer as a daemon.
func vmEcho(ns, name string, ports ...int) string {
	return fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  daemons:
    - { name: echo, run: %s }
`, name, ns, yamlStr("exec "+remote.Join(echoArgv(name, ports...))))
}

// boxEcho is a docker silo running metalEchoServer as its command.
func boxEcho(ns, name string, ports ...int) string {
	return fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: docker
  container: { image: docker.io/library/python:3.12-slim, command: %s }
  resources: { cpu: 1, memory: 256Mi }
`, name, ns, yamlList(echoArgv(name, ports...)))
}

func randomValue(t *testing.T, prefix string) string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// metalSilos reads kvo get silos -o json: an array, a list, or (one item) the object itself.
func metalSilos(out string) []*v1.Silo {
	data := []byte(strings.TrimSpace(out))
	var raws []json.RawMessage
	if json.Unmarshal(data, &raws) != nil {
		var list struct {
			Items []json.RawMessage `json:"items"`
			Kind  string            `json:"kind"`
		}
		switch {
		case json.Unmarshal(data, &list) != nil:
			return nil
		case list.Items != nil || strings.HasSuffix(list.Kind, "List"):
			raws = list.Items
		default:
			raws = []json.RawMessage{data}
		}
	}
	var silos []*v1.Silo
	for _, raw := range raws {
		var s v1.Silo
		if json.Unmarshal(raw, &s) == nil && s.Name != "" {
			silos = append(silos, &s)
		}
	}
	return silos
}

// TestMetalReset only resets the machine and runs the checklist (after a run kept with
// KEVASO_E2E_KEEP, or to check the machine). It makes no cluster.
func TestMetalReset(t *testing.T) {
	d := metalDriver(t)
	defer func() { _ = d.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if _, err := d.RecordBaseline(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("the machine is clean: every checklist item passed")
}

// TestMetalCheck only runs the checklist and the baseline comparison, changing nothing: is the
// machine clean now (after kvoadm reset, say)?
func TestMetalCheck(t *testing.T) {
	d := metalDriver(t)
	defer func() { _ = d.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	base, err := d.Baseline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Check(ctx, &base); err != nil {
		t.Fatal(err)
	}
	t.Log("the machine is clean: every checklist item passed, and it matches its baseline")
}

func jsonUnmarshal(s string, v any) error { return json.Unmarshal([]byte(s), v) }
