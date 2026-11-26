//go:build metal

package e2e

// Networking v2 on the two machines (idealization/networking-v2.md): host addresses, an IP of
// type Host, HostPort services on an IP and on a worker, egress from an IP, several services on
// one silo with readiness and DNS per service, an IPSet for a SiloSet's own addresses, and the
// namespace cascade.
//
// The extra addresses are private ones (internal host addresses in 10.77.0.0/24): the lab
// machines have no second public address. The test links the two machines with a VXLAN
// (kvtlab0, over UDP between their external IPs; the reset removes kvt* links) and routes each
// extra address to the machine that has it, so the other machine is the outside client. Kevaso
// itself puts an address on the host (a /32 labelled :kv) once a silo holds its IP.
//
// Listens on: 18301, 18302 on machine 2's external IP (worker: external); 18300, 18303 only on
// the private addresses; UDP 4799 between the two machines (the lab link).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvoadm"
)

const (
	netLink  = "kvtlab0"
	netLink1 = "10.77.9.1" // machine 1's end of the lab link
	netLink2 = "10.77.9.2" // machine 2's end
	netMail  = "10.77.0.1" // host address lab-a on machine 1: IP mail
	netEdge0 = "10.77.0.2" // host address lab-b on machine 1: IPSet edge, member 0
	netEdge1 = "10.77.0.3" // host address lab-c on machine 2: IPSet edge, member 1
)

// labLink links the machines with a VXLAN and routes each private address to its machine. It
// goes with the test.
func (p *pair) labLink() {
	p.t.Helper()
	m1, m2 := p.m1.cfg.ExternalIP, p.m2.cfg.ExternalIP
	link := func(c *mt, local, remote, mine string, routes ...string) {
		script := fmt.Sprintf(`set -e
ip link del %[1]s 2>/dev/null || true
dev=$(ip -4 -o addr show | awk '$4 ~ /^%[2]s\// {print $2; exit}')
ip link add %[1]s type vxlan id 77 local %[2]s remote %[3]s dstport 4799 dev "$dev"
ip addr add %[4]s/30 dev %[1]s
ip link set %[1]s up
`, netLink, local, remote, mine)
		for _, r := range routes {
			script += fmt.Sprintf("ip route replace %s/32 dev %s\n", r, netLink)
		}
		c.mustSh(script)
	}
	link(p.c1, m1, m2, netLink1, netEdge1)
	link(p.c2, m2, m1, netLink2, netMail, netEdge0)
	p.t.Cleanup(func() {
		for _, c := range []*mt{p.c1, p.c2} {
			_, _ = c.sh("ip link del " + netLink + " 2>/dev/null; systemctl stop kvt-whoami 2>/dev/null; true")
		}
	})
	p.c2.eventually("the lab link answers", time.Minute, func() (bool, string) {
		out, err := p.c2.sh("ping -c1 -W2 " + netLink1)
		return err == nil, out
	})
}

// curlFrom is an HTTP GET from a machine (its body, or what went wrong).
func curlFrom(c *mt, addr string, port int) (bool, string) {
	out, err := c.sh(fmt.Sprintf("curl -sS --max-time 4 http://%s:%d/ 2>&1", addr, port))
	return err == nil, strings.TrimSpace(out)
}

// TestMetal2NetV2 is networking v2 on real hosts: see the file's comment.
func TestMetal2NetV2(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	p.labLink()
	c := p.c1
	ns := "netv2"
	c.namespace(ns)

	// --- host addresses -------------------------------------------------------------------
	p.kvoadm("host", "addresses", metalHost, "add", "lab-a", netMail, "--internal")
	p.kvoadm("host", "addresses", metalHost, "add", "lab-b", netEdge0, "--internal")
	p.kvoadm("host", "addresses", metalHost2, "add", "lab-c", netEdge1, "--internal")
	t.Cleanup(func() { // after the namespace is gone (cleanups run last-in first)
		for _, a := range [][2]string{{metalHost, "lab-a"}, {metalHost, "lab-b"}, {metalHost2, "lab-c"}} {
			_, _ = p.kvoadmOut("host", "addresses", a[0], "remove", a[1])
		}
	})
	list := p.kvoadmMust("host", "addresses", metalHost, "list")
	for _, w := range []string{"lab-a", netMail, "lab-b", netEdge0, "internal"} {
		if !strings.Contains(list, w) {
			t.Errorf("addresses list of %s lacks %q:\n%s", metalHost, w, list)
		}
	}

	// --- an IP of type Host, a silo with two services, egress from the IP -----------------
	c.must("", "create", "ip", "mail", "-n", ns, "--type", "Host", "--host-address", "lab-a")
	c.apply(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: out, namespace: ` + ns + ` }
spec:
  egress: [{ to: "` + netLink2 + `/32", ports: ["18309"] }]
---
` + boxEcho(ns, "mail", 8080, 18300) + `  ports: [{ name: smtp, port: 8080 }, { name: pub, port: 18300 }]
  grants: [out]
  availability: { onHostLoss: Recreate } # a fresh copy may move: only the IP keeps it here
  services:
    - ports: [{ port: smtp, allowFrom: [caller] }]
    - name: mail-pub
      type: HostPort
      hostPort: { ip: mail }
      ports: [{ port: pub }]
  network:
    egress: { source: { ip: mail } }
---
` + boxEcho(ns, "caller", 8080) + on(metalHost2) + "---\n" + boxEcho(ns, "stranger", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "mail", "caller", "stranger")
	if h := c.silo(ns, "mail").Status.Host; h != metalHost {
		t.Errorf("mail runs on %s: an IP of type Host pins it to %s", h, metalHost)
	}
	var ip v1.IP
	if err := json.Unmarshal([]byte(c.must("", "get", "ip", "mail", "-n", ns, "-o", "json")), &ip); err != nil {
		t.Fatal(err)
	}
	if ip.Spec.Type != v1.IPTypeHost || ip.Status.Address != netMail || ip.Status.Host != metalHost || ip.Status.Holder == nil {
		t.Errorf("IP mail: type %s, address %s, host %s, holder %v; want Host, %s, %s, held", ip.Spec.Type, ip.Status.Address, ip.Status.Host, ip.Status.Holder, netMail, metalHost)
	}
	t.Logf("kvo get ips:\n%s", c.must("", "get", "ips", "-n", ns))

	c.eventually("hostPort ip answers on its address (from machine 2, over the lab link)", 2*time.Minute, func() (bool, string) {
		ok, out := curlFrom(p.c2, netMail, 18300)
		return ok && strings.Contains(out, "mail 18300"), out
	})
	c.eventually("Kevaso put the address on machine 1 (a :kv /32)", time.Minute, func() (bool, string) {
		out, _ := p.c1.sh("ip -4 -o addr show label '*:kv'")
		return strings.Contains(out, netMail+"/32"), out
	})
	if ok, got := openOn(p.m1, 18300); ok {
		t.Errorf("hostPort ip also answers on machine 1's main address, from this Mac: %s", got)
	}
	if ok, got := curlFrom(p.c2, p.m1.cfg.ExternalIP, 18300); ok {
		t.Errorf("hostPort ip also answers on machine 1's main address, from machine 2: %s", got)
	}

	desc := c.must("", "describe", "silo", "mail", "-n", ns)
	if !strings.Contains(strings.Join(strings.Fields(desc), " "), "Can move: no: pinned to "+metalHost+" (IP mail is that host's address)") {
		t.Errorf("describe silo mail doesn't say it's pinned:\n%s", desc)
	}
	t.Logf("describe silo mail:\n%s", desc)
	if out, code := c.kvo("", "move", "silo", "mail", "-n", ns, "--to", metalHost2, "--recreate"); code == 0 || !strings.Contains(out, "IP mail is host "+metalHost+"'s address") {
		t.Errorf("a move off the IP's host: exit %d %q", code, out)
	} else {
		t.Logf("move refused: %s", strings.TrimSpace(out))
	}
	if out, code := p.kvoadmOut("host", "addresses", metalHost, "remove", "lab-a"); code == 0 || !strings.Contains(out, "reserved by IP "+ns+"/mail") {
		t.Errorf("removing a reserved address: exit %d %q", code, out)
	} else {
		t.Logf("remove refused: %s", strings.TrimSpace(out))
	}

	// Egress from the IP: machine 2 answers with the address it sees.
	p.c2.mustSh(`systemctl stop kvt-whoami 2>/dev/null || true
systemd-run --unit=kvt-whoami python3 -c '
import http.server as h
class H(h.BaseHTTPRequestHandler):
    def do_GET(s):
        b = s.client_address[0].encode(); s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
h.HTTPServer(("` + netLink2 + `", 18309), H).serve_forever()'`)
	c.eventually("egress source ip leaves from the IP's address", 2*time.Minute, func() (bool, string) {
		out, _ := c.in(ns, "mail", `python3 -c "import urllib.request as u; print(u.urlopen('http://`+netLink2+`:18309/', timeout=5).read().decode())" 2>&1`)
		return strings.TrimSpace(out) == netMail, out
	})

	// The Internal service on the same silo: allowFrom, across the mesh.
	c.eventually("the Internal service answers the silo allowFrom names", 2*time.Minute, func() (bool, string) {
		out, _ := c.in(ns, "caller", `python3 -c "import urllib.request as u; print(u.urlopen('http://mail:8080/', timeout=5).read().decode())" 2>&1`)
		return strings.Contains(out, "mail 8080"), out
	})
	c.holds("a silo allowFrom doesn't name can't connect", 10*time.Second, func() (bool, string) {
		out, _ := c.in(ns, "stranger", `python3 -c "import urllib.request as u; print(u.urlopen('http://mail:8080/', timeout=5).read().decode())" 2>&1`)
		return !strings.Contains(out, "mail 8080"), out
	})

	// --- worker: external on the other host; readiness and DNS per service ----------------
	c.apply(boxEcho(ns, "web", 18301, 18302) + on(metalHost2) + `  ports: [{ name: a, port: 18301 }, { name: b, port: 18302 }]
  services:
    - name: web-always
      type: HostPort
      routeWhen: running
      ports: [{ port: a }]
    - name: web-gated
      type: HostPort
      hostPort: { worker: external }
      routeWhen: ready
      ports: [{ port: b }]
  probes:
    readiness: { exec: { command: [test, -f, /tmp/ready] }, period: 2s, successes: 1, failures: 1 }
`)
	c.waitRunning(ns, 10*time.Minute, "web")
	name := func(svc string) string {
		out, _ := c.in(ns, "caller", "getent ahostsv4 "+svc+"."+ns+"."+c.suffix+" | awk 'NR==1 {print $1}'")
		return strings.TrimSpace(out)
	}
	c.eventually("worker: external answers on its host's external IP", 2*time.Minute, func() (bool, string) { return openOn(p.m2, 18301) })
	if ok, got := openOn(p.m1, 18301); ok {
		t.Errorf("worker: external also answers on the other host: %s", got)
	}
	c.holds("not ready: the gated service is held (port closed, no name) while the other is routed", 15*time.Second, func() (bool, string) {
		gatedOpen, g := openOn(p.m2, 18302)
		alwaysOpen, a := openOn(p.m2, 18301)
		ng, na := name("web-gated"), name("web-always")
		return !gatedOpen && alwaysOpen && ng == "" && na != "", fmt.Sprintf("gated %v %s %q; always %v %s %q", gatedOpen, g, ng, alwaysOpen, a, na)
	})
	c.in(ns, "web", "touch /tmp/ready")
	c.eventually("ready: the gated service opens and its name answers", time.Minute, func() (bool, string) {
		ok, got := openOn(p.m2, 18302)
		return ok && name("web-gated") != "", got
	})
	if a, b := name("web-always"), name("web-gated"); a != c.silo(ns, "web").Status.SiloIP || b != a {
		t.Errorf("per-service names: web-always %q, web-gated %q, want the silo IP %s", a, b, c.silo(ns, "web").Status.SiloIP)
	}
	if got := name("mail-pub"); got == "" {
		t.Errorf("mail-pub (hostPort ip) has no name")
	} else {
		t.Logf("mail-pub resolves to %s, mail to %s", got, name("mail"))
	}

	// --- an IPSet Static with host-address members, for a SiloSet with own -----------------
	echo := boxEcho(ns, "edge", 18303)
	tmpl := echo[strings.Index(echo, "  runtime:"):]
	c.apply(`apiVersion: kevaso/v1
kind: IPSet
metadata: { name: edge, namespace: ` + ns + ` }
spec:
  type: Static
  members: [{ hostAddress: lab-b }, { hostAddress: lab-c }]
---
apiVersion: kevaso/v1
kind: SiloSet
metadata: { name: edge, namespace: ` + ns + ` }
spec:
  instances: 2
  ips: edge
  template:
` + indent(tmpl+`  ports: [{ name: pub, port: 18303 }]
  services:
    - name: edge
      type: HostPort
      hostPort: { own: true }
      ports: [{ port: pub }]
`, "  "))
	c.waitRunning(ns, 15*time.Minute, "edge-0", "edge-1")
	for i, want := range []string{metalHost, metalHost2} {
		if h := c.silo(ns, fmt.Sprintf("edge-%d", i)).Status.Host; h != want {
			t.Errorf("edge-%d runs on %s: its member's address is on %s", i, h, want)
		}
	}
	c.eventually("edge-0 answers on member 0's address (machine 1), from machine 2", 2*time.Minute, func() (bool, string) {
		ok, out := curlFrom(p.c2, netEdge0, 18303)
		return ok && strings.Contains(out, "edge 18303"), out
	})
	c.eventually("edge-1 answers on member 1's address (machine 2), from machine 1", 2*time.Minute, func() (bool, string) {
		ok, out := curlFrom(p.c1, netEdge1, 18303)
		return ok && strings.Contains(out, "edge 18303"), out
	})
	if ok, got := openOn(p.m1, 18303); ok {
		t.Errorf("own also answers on machine 1's main address: %s", got)
	}
	t.Logf("kvo get ipsets:\n%s\nkvo get ips:\n%s", c.must("", "get", "ipsets", "-n", ns), c.must("", "get", "ips", "-n", ns))

	// --- the namespace cascade ---------------------------------------------------------------
	out, code := c.kvo("", "delete", "namespace", ns)
	if code == 0 || !strings.Contains(out, "still holds resources") || !strings.Contains(out, "--yes") {
		t.Fatalf("delete namespace without a terminal or --yes: exit %d %q", code, out)
	}
	t.Logf("no terminal: %s", strings.TrimSpace(out))
	// While it empties, note when the silos and the IPs are gone: silos first (stop silos, then
	// release IPs). kvo prints a step only when it sees one; on these hosts each takes under its
	// one-second look, so its output may hold none.
	gone := map[string]time.Time{}
	var goneMu sync.Mutex
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		for end := time.Now().Add(15 * time.Minute); time.Now().Before(end); {
			for _, kind := range []string{"silos", "ips"} {
				out, code := c.kvo("", "get", kind, "-n", ns, "-o", "json")
				goneMu.Lock()
				if _, ok := gone[kind]; !ok && (code != 0 && strings.Contains(out, "NotFound") || code == 0 && len(objectNames(out)) == 0) {
					gone[kind] = time.Now()
				}
				done := len(gone) == 2
				goneMu.Unlock()
				if done {
					return
				}
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
	start := time.Now()
	steps := p.deleteNamespaceAtTerminal(ns)
	<-watching
	t.Logf("kvo delete namespace %s, answered y at its terminal (%s):\n%s", ns, time.Since(start).Round(time.Second), steps)
	goneMu.Lock()
	if gone["silos"].IsZero() || gone["ips"].IsZero() || gone["silos"].After(gone["ips"]) {
		t.Errorf("silos gone at %v, IPs at %v: the silos go first", gone["silos"].Sub(start), gone["ips"].Sub(start))
	} else {
		t.Logf("silos gone after %v, IPs after %v", gone["silos"].Sub(start).Round(10*time.Millisecond), gone["ips"].Sub(start).Round(10*time.Millisecond))
	}
	goneMu.Unlock()
	order := []string{"still holds resources", "Are you sure?", "namespace/" + ns + " deleted"}
	at := 0
	for _, w := range order {
		i := strings.Index(steps[at:], w)
		if i < 0 {
			t.Errorf("the cascade's output lacks %q after position %d (order %v):\n%s", w, at, order, steps)
			break
		}
		at += i
	}
	for _, kind := range []string{"silos", "ips", "ipsets", "grants"} {
		if out, _ := c.kvo("", "get", kind, "-n", ns, "-o", "json"); len(objectNames(out)) > 0 {
			t.Errorf("%s left in %s: %s", kind, ns, out)
		}
	}
	if out, code := c.kvo("", "get", "namespace", ns); code == 0 {
		t.Errorf("namespace %s is still there: %s", ns, out)
	}
	for _, m := range []*mt{p.c1, p.c2} {
		m.eventually("no silo and no held address left on the machine", 2*time.Minute, func() (bool, string) {
			out, _ := m.sh("docker ps -q --filter label=kevaso.com/namespace=" + ns + "; ip -4 -o addr | grep -E '10\\.77\\.0\\.' ; true")
			return strings.TrimSpace(out) == "", out
		})
	}
	for _, a := range [][2]string{{metalHost, "lab-a"}, {metalHost, "lab-b"}, {metalHost2, "lab-c"}} {
		p.kvoadm("host", "addresses", a[0], "remove", a[1])
	}
	if list := p.kvoadmMust("host", "addresses", metalHost, "list"); strings.Contains(list, "lab-a") {
		t.Errorf("lab-a still listed after remove:\n%s", list)
	}
}

// indent puts prefix before every non-empty line.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}

// kvoadmOut runs kvoadm against the cluster: its output and exit code.
func (p *pair) kvoadmOut(args ...string) (string, int) {
	var o bytes.Buffer
	code := kvoadm.Run(p.c1.ctx, args, strings.NewReader(""), &o, &o)
	return o.String(), code
}

// kvoadmMust runs kvoadm and fails the test unless it exits 0.
func (p *pair) kvoadmMust(args ...string) string {
	p.t.Helper()
	out, code := p.kvoadmOut(args...)
	if code != 0 {
		p.t.Fatalf("kvoadm %v: exit %d\n%s", args, code, out)
	}
	return out
}

// deleteNamespaceAtTerminal runs the kvo binary's delete namespace under a terminal (script(1)
// gives it one), answers y once it asks, and returns all it printed.
func (p *pair) deleteNamespaceAtTerminal(ns string) string {
	p.t.Helper()
	dir := p.t.TempDir()
	bin := filepath.Join(dir, "kvo")
	if b, err := exec.Command("go", "build", "-o", bin, "kevaso.com/core/cmd/kvo").CombinedOutput(); err != nil {
		p.t.Fatalf("build kvo: %v\n%s", err, b)
	}
	cmd := exec.Command("script", "-q", "/dev/null", bin, "delete", "namespace", ns)
	cmd.Env = os.Environ()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		p.t.Fatal(err)
	}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var mu sync.Mutex
	var all strings.Builder
	asked := make(chan struct{})
	go func() {
		r := bufio.NewReader(pr)
		once := sync.Once{}
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			mu.Lock()
			all.Write(buf[:n])
			if strings.Contains(all.String(), "Are you sure?") {
				once.Do(func() { close(asked) })
			}
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	select {
	case <-asked:
		_, _ = io.WriteString(stdin, "y\n")
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		p.t.Fatalf("kvo delete namespace never asked:\n%s", all.String())
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(15 * time.Minute):
		_ = cmd.Process.Kill()
		err = <-done
	}
	_ = stdin.Close()
	_ = pw.Close()
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		p.t.Errorf("kvo delete namespace %s: %v\n%s", ns, err, all.String())
	}
	return strings.ReplaceAll(all.String(), "\r", "")
}
