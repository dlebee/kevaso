//go:build metal

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/sshboot"
)

// Names these tests create. They start with k so a lab kept between runs is easy to tell from
// the cluster's own objects. k124a and k124b are the two namespaces of the egress test (a and b).
const (
	labEgressA    = "k124a"
	labEgressB    = "k124b"
	labHardNS     = "k125"
	labHardUser   = "kvthard"
	labNSX        = "k128x"
	labNSY        = "k128y"
	labBind       = "to-ci"
	labSA         = "ci"
	labAllowSilo  = "api"
	labForgedHost = "forged"
	labListenPort = 8080
	// labStandIn is TEST-NET-3. The probe dials it so the packet leaves the silo and the egress
	// gate judges the name (the same stand-in as TestMetal2EgressByNameRefusesPrivate).
	labStandIn    = "203.0.113.9"
	labPublicName = "example.com"
	labImage      = "docker.io/library/python:3.12-slim"
)

// labTLS is a client inside a silo: one TLS connection to dest:port with SNI name, then an HTTP
// line. A refused connection exits non-zero. A completed handshake prints the answer.
const labTLS = `import socket, ssl, sys
name, dest, port, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = socket.create_connection((dest, port), timeout)
s.settimeout(timeout)
tls = ctx.wrap_socket(s, server_hostname=name)
tls.settimeout(timeout)
tls.sendall(b"GET / HTTP/1.0\r\nHost: " + name.encode() + b"\r\n\r\n")
sys.stdout.buffer.write(tls.recv(180))
`

// TestLabEgressGateClosedRanges is K-124 on a worktree lab (testbed/lab): a grant cannot open a
// silo's address, loopback, link-local or the mesh, and a name is not dialled to one of them
// when the grant also says 0.0.0.0/0. It does not call metal(), so the metal suite's reset does
// not run against the lab. Source testbed/lab/.labs/NAME/env.sh first.
func TestLabEgressGateClosedRanges(t *testing.T) {
	admin := labAdmin(t)
	if os.Getenv("KEVASO_METAL_KEY") == "" {
		t.Fatal("KEVASO_METAL_KEY comes from the lab env file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	t.Cleanup(cancel)
	var node *labNode
	t.Cleanup(func() {
		if node != nil {
			_ = node.d.Close()
		}
		labSweep(ctx, t, admin, [][2]string{{labEgressA, "target"}, {labEgressB, "probe"}},
			[][3]string{
				{"grant", labEgressB, "out"},
				{"grant", labEgressB, "closed-silo"},
				{"grant", labEgressB, "closed-loop"},
				{"grant", labEgressB, "closed-link"},
				{"grant", labEgressB, "closed-mesh"},
			}, []string{labEgressA, labEgressB})
	})

	labNamespace(t, ctx, admin, labEgressA)
	labNamespace(t, ctx, admin, labEgressB)

	// target listens in namespace a. Its service names nobody in namespace b, so b has no
	// allowFrom path to it. probe, in b, is the client.
	labKvo(t, ctx, boxEcho(labEgressA, "target", labListenPort)+fmt.Sprintf(`  ports: [{ name: http, port: %d }]
  service:
    ports: [{ port: http }]
`, labListenPort), "apply", "--context", admin, "-f", "-")
	target := labWaitRunning(t, ctx, admin, labEgressA, "target", 20*time.Minute)
	siloIP := target.Status.SiloIP
	addr, err := netip.ParseAddr(siloIP)
	if err != nil || !netip.MustParsePrefix("10.64.0.0/16").Contains(addr) {
		t.Fatalf("target's address %q is outside the silo range 10.64.0.0/16", siloIP)
	}
	heard := labAwaitListen(t, ctx, admin, labEgressA, "target")
	if !strings.Contains(heard, "target") {
		t.Fatalf("target listening on %d: %s", labListenPort, heard)
	}
	t.Logf("target %s/%s on %s port %d, no allowFrom for %s", labEgressA, "target", siloIP, labListenPort, labEgressB)

	// (a) Admission. Each rule is its own grant, so the 422 is about that one range.
	labRefuseGrant(t, ctx, admin, labEgressB, "closed-silo", siloIP, "10.64.0.0/16")
	labRefuseGrant(t, ctx, admin, labEgressB, "closed-loop", "127.0.0.1", "127.0.0.0/8")
	labRefuseGrant(t, ctx, admin, labEgressB, "closed-link", "169.254.169.254", "169.254.0.0/16")
	labRefuseGrant(t, ctx, admin, labEgressB, "closed-mesh", "10.62.0.0/16", "the mesh range")

	// (b) sslip.io encodes the address in the name, the same way TestMetal2EgressByNameRefusesPrivate
	// reaches loopback and link-local. The lab's dnsmasq answers any name under LAB_NAME.lab.test
	// with the system node (10.77.N.10), so that name cannot stand in for these addresses.
	// 0.0.0.0/0 and the names are on the port target listens on, which is what the gate redirects.
	// example.com is the ordinary name, on 443.
	siloName := strings.ReplaceAll(siloIP, ".", "-") + ".sslip.io"
	loopName := "127-0-0-1.sslip.io"
	linkName := "169-254-169-254.sslip.io"
	grant := fmt.Sprintf(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: out, namespace: %s }
spec:
  egress:
    - { to: %s, ports: ["%d"] }
    - { to: %s, ports: ["%d"] }
    - { to: %s, ports: ["%d"] }
    - { to: "0.0.0.0/0", ports: ["%d"] }
    - { to: %s }
`, labEgressB, yamlStr(siloName), labListenPort, yamlStr(loopName), labListenPort, yamlStr(linkName), labListenPort, labListenPort, yamlStr(labPublicName))
	labKvo(t, ctx, grant, "apply", "--context", admin, "-f", "-")
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: probe, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
  grants: [out]
`, labEgressB, labImage), "apply", "--context", admin, "-f", "-")
	probe := labWaitRunning(t, ctx, admin, labEgressB, "probe", 20*time.Minute)
	node = labDial(t, ctx, labGetHost(t, ctx, admin, probe.Status.Host), os.Getenv("KEVASO_METAL_KEY"))
	since := strings.TrimSpace(node.must("date -u '+%Y-%m-%d %H:%M:%S'"))
	for _, c := range []struct{ name, ip string }{
		{siloName, siloIP},
		{loopName, "127.0.0.1"},
		{linkName, "169.254.169.254"},
	} {
		labExpectBlocked(t, ctx, admin, node, since, c.name, c.ip)
	}

	// (c) A name the grant allows, to a public address on 443.
	labExpectOpen(t, ctx, admin, labPublicName)
}

// TestLabAPIHardening is K-125 and K-128 on a worktree lab. A namespace admin's create stores
// none of the status they sent, and the scheduler places the silo. A namespace stays while a
// RoleBinding or an allowFrom outside it still names it. It does not call metal().
func TestLabAPIHardening(t *testing.T) {
	admin := labAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() {
		labSweep(ctx, t, admin, [][2]string{{labHardNS, "web"}, {labNSY, labAllowSilo}},
			[][3]string{
				{"ip", labHardNS, "pub"},
				{"rolebinding", labHardNS, labHardUser + "-admin"},
				{"rolebinding", labNSY, labBind},
			}, []string{labHardNS, labNSX, labNSY})
	})

	// (a) The forged status is on the create. What is stored has none of it, and the host the
	// scheduler writes is a worker.
	labNamespace(t, ctx, admin, labHardNS)
	user := labLoginAdmin(t, ctx, admin, labHardUser, labHardNS)
	ipYAML := fmt.Sprintf(`apiVersion: kevaso/v1
kind: IP
metadata: { name: pub, namespace: %s }
spec: { class: ip-pool }
status: { address: "203.0.113.50", handle: "res-1" }
`, labHardNS)
	if out := labKvo(t, ctx, ipYAML, "apply", "--context", user, "-f", "-"); !strings.Contains(out, "created") {
		t.Fatalf("IP create: %s", out)
	}
	var ip v1.IP
	if err := json.Unmarshal([]byte(jsonObject(labKvo(t, ctx, "", "get", "--context", admin, "ip", "pub", "-n", labHardNS, "-o", "json"))), &ip); err != nil {
		t.Fatal(err)
	}
	if ip.Status.Address != "" || ip.Status.Handle != "" {
		t.Fatalf("stored IP status %+v, want empty address and handle", ip.Status)
	}
	t.Logf("IP pub stored with empty address and handle")

	siloYAML := fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: web, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
status:
  host: %s
  volumes:
    - { name: data, class: local, attachedTo: %s, device: "/dev/vdb" }
`, labHardNS, labImage, labForgedHost, labForgedHost)
	if out := labKvo(t, ctx, siloYAML, "apply", "--context", user, "-f", "-"); !strings.Contains(out, "created") {
		t.Fatalf("Silo create: %s", out)
	}
	fresh := labGetSilo(t, ctx, admin, labHardNS, "web")
	if fresh.Status.Host == labForgedHost || len(fresh.Status.Volumes) != 0 {
		t.Fatalf("stored silo status host %q volumes %+v", fresh.Status.Host, fresh.Status.Volumes)
	}
	t.Logf("silo web just after create: phase %q host %q volumes %d", fresh.Status.Phase, fresh.Status.Host, len(fresh.Status.Volumes))
	placed := labWaitHost(t, ctx, admin, labHardNS, "web", 5*time.Minute)
	if placed.Status.Host != "w1" && placed.Status.Host != "w2" {
		t.Fatalf("scheduler placed web on %q, want a lab worker w1 or w2", placed.Status.Host)
	}
	if len(placed.Status.Volumes) != 0 {
		t.Fatalf("placed silo volumes %+v", placed.Status.Volumes)
	}
	t.Logf("silo web placed on %s (%s), forged host %s absent, no volumes", placed.Status.Host, placed.Status.Phase, labForgedHost)

	// (b) x is k128x, y is k128y. The binding's subject is a service account in x. The account
	// object is not created, so x itself holds nothing: the 409 is the outside names. allowFrom
	// names a silo x/ci, which is the same name as that account; no such silo is created.
	labNamespace(t, ctx, admin, labNSX)
	labNamespace(t, ctx, admin, labNSY)
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: RoleBinding
metadata: { name: %s, namespace: %s }
roleRef: { kind: ClusterRole, name: viewer }
subjects: [{ kind: ServiceAccount, name: %s, namespace: %s }]
`, labBind, labNSY, labSA, labNSX), "apply", "--context", admin, "-f", "-")
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
  ports: [{ name: http, port: %d }]
  service:
    ports: [{ port: http, allowFrom: [%s] }]
`, labAllowSilo, labNSY, labImage, labListenPort, yamlStr(labNSX+"/"+labSA)), "apply", "--context", admin, "-f", "-")

	out, code := labKvoCode(ctx, "", "delete", "--context", admin, "namespace", labNSX)
	if code == 0 || !strings.Contains(out, "409") || !strings.Contains(out, "named from outside") ||
		!strings.Contains(out, labNSY+"/"+labBind) || !strings.Contains(out, labNSY+"/"+labAllowSilo) {
		t.Fatalf("deleting %s: exit %d, want 409 naming %s/%s and %s/%s\n%s",
			labNSX, code, labNSY, labBind, labNSY, labAllowSilo, out)
	}
	t.Logf("delete %s: %s", labNSX, oneLine(out))

	labKvo(t, ctx, "", "delete", "--context", admin, "rolebinding", labBind, "-n", labNSY)
	labKvo(t, ctx, "", "delete", "--context", admin, "silo", labAllowSilo, "-n", labNSY)
	labWaitDeleted(t, ctx, admin, "silo", labNSY, labAllowSilo)
	gone := labKvo(t, ctx, "", "delete", "--context", admin, "namespace", labNSX)
	t.Logf("delete %s after the binding and the silo were removed: %s", labNSX, oneLine(gone))
}

// labAdmin is the lab env's current context. Without LAB_NAME the test skips.
func labAdmin(t *testing.T) string {
	t.Helper()
	if os.Getenv("LAB_NAME") == "" {
		t.Skip("LAB_NAME is unset: source testbed/lab/.labs/NAME/env.sh (this test runs against a worktree lab)")
	}
	cfgPath := os.Getenv("KVO_CONFIG")
	if cfgPath == "" {
		t.Fatal("KVO_CONFIG comes from the lab env file")
	}
	kcfg, err := kvoconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if kcfg.CurrentContext == "" {
		t.Fatal("the lab config has no current context")
	}
	return kcfg.CurrentContext
}

func labNamespace(t *testing.T, ctx context.Context, admin, name string) {
	t.Helper()
	labKvo(t, ctx, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: "+name+" }\n",
		"apply", "--context", admin, "-f", "-")
}

func labRefuseGrant(t *testing.T, ctx context.Context, admin, ns, name, to, rng string) {
	t.Helper()
	body := fmt.Sprintf(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: %s, namespace: %s }
spec:
  egress:
    - { to: %s }
`, name, ns, yamlStr(to))
	out, code := labKvoCode(ctx, body, "apply", "--context", admin, "-f", "-")
	if code == 0 || !strings.Contains(out, "422") || !strings.Contains(out, rng) {
		t.Fatalf("grant %s egress %s: exit %d, want 422 naming %s\n%s", name, to, code, rng, out)
	}
	t.Logf("grant %s: %s", name, oneLine(out))
}

func labGetSilo(t *testing.T, ctx context.Context, admin, ns, name string) *v1.Silo {
	t.Helper()
	out := labKvo(t, ctx, "", "get", "--context", admin, "silo", name, "-n", ns, "-o", "json")
	var s v1.Silo
	if err := json.Unmarshal([]byte(jsonObject(out)), &s); err != nil {
		t.Fatalf("silo %s/%s: %v\n%s", ns, name, err, out)
	}
	return &s
}

func labWaitRunning(t *testing.T, ctx context.Context, admin, ns, name string, within time.Duration) *v1.Silo {
	t.Helper()
	deadline := time.Now().Add(within)
	var last string
	for {
		out, code := labKvoCode(ctx, "", "get", "--context", admin, "silo", name, "-n", ns, "-o", "json")
		var s v1.Silo
		if code == 0 && json.Unmarshal([]byte(jsonObject(out)), &s) == nil {
			switch s.Status.Phase {
			case "Running":
				return &s
			case "Failed":
				t.Fatalf("silo %s/%s failed:\n%s", ns, name, out)
			}
			last = s.Status.Phase
		} else {
			last = strings.TrimSpace(out)
		}
		if time.Now().After(deadline) {
			t.Fatalf("silo %s/%s not running after %s (%s)", ns, name, within, last)
		}
		time.Sleep(5 * time.Second)
	}
}

// labWaitHost waits until the scheduler has set status.host. A phase of Failed still counts:
// the host is written when the silo is placed, which is before the image is pulled.
func labWaitHost(t *testing.T, ctx context.Context, admin, ns, name string, within time.Duration) *v1.Silo {
	t.Helper()
	deadline := time.Now().Add(within)
	var last string
	for {
		out, code := labKvoCode(ctx, "", "get", "--context", admin, "silo", name, "-n", ns, "-o", "json")
		var s v1.Silo
		if code == 0 && json.Unmarshal([]byte(jsonObject(out)), &s) == nil {
			if s.Status.Host == labForgedHost {
				t.Fatalf("silo %s/%s is on the forged host", ns, name)
			}
			if s.Status.Host != "" {
				return &s
			}
			last = s.Status.Phase
		} else {
			last = strings.TrimSpace(out)
		}
		if time.Now().After(deadline) {
			t.Fatalf("silo %s/%s has no host after %s (%s)", ns, name, within, last)
		}
		time.Sleep(2 * time.Second)
	}
}

func labWaitDeleted(t *testing.T, ctx context.Context, admin, kind, ns, name string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	var last string
	for {
		out, code := labKvoCode(ctx, "", "get", "--context", admin, kind, name, "-n", ns)
		last = strings.TrimSpace(out)
		if code != 0 && strings.Contains(out, "NotFound") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %s/%s still there:\n%s", kind, ns, name, last)
		}
		time.Sleep(2 * time.Second)
	}
}

func labAwaitListen(t *testing.T, ctx context.Context, admin, ns, silo string) string {
	t.Helper()
	script := fmt.Sprintf("import socket; s=socket.create_connection(('127.0.0.1',%d),5); s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); print(s.recv(400).decode())", labListenPort)
	deadline := time.Now().Add(30 * time.Second)
	var last string
	var code int
	for {
		last, code = labExec(ctx, admin, ns, silo, "python3", "-c", script)
		if code == 0 && strings.Contains(last, silo) {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s/%s is not listening on %d (exit %d)\n%s", ns, silo, labListenPort, code, last)
		}
		time.Sleep(2 * time.Second)
	}
}

func labExec(ctx context.Context, admin, ns, silo string, argv ...string) (string, int) {
	args := []string{"exec", "--context", admin, "silo", silo, "-n", ns, "--"}
	args = append(args, argv...)
	return labKvoCode(ctx, "", args...)
}

func labExpectBlocked(t *testing.T, ctx context.Context, admin string, node *labNode, since, name, ip string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var last string
	var code int
	var j string
	for {
		last, code = labExec(ctx, admin, labEgressB, "probe", "python3", "-c", labTLS, name, labStandIn, fmt.Sprint(labListenPort), "8")
		if code == 0 && strings.Contains(last, "HTTP/") {
			t.Fatalf("%s through %s reached %s:\n%s", name, labStandIn, ip, last)
		}
		j = node.must("journalctl -u kevasod --no-pager --since " + sshboot.Quote(since) + " | grep -F 'gate: BLOCKED' || true")
		if labBlocked(j, labEgressB+"/probe", name, ip) {
			t.Logf("%s → %s refused (exit %d)", name, ip, code)
			return
		}
		if time.Now().After(deadline) {
			node.fatal(t, "gate", fmt.Sprintf("no 'gate: BLOCKED … %s … resolves to %s … which a grant never opens' line (exit %d)\n%s\n%s",
				name, ip, code, last, j))
		}
		time.Sleep(3 * time.Second)
	}
}

func labBlocked(j, key, name, ip string) bool {
	want := "resolves to " + ip + " ("
	for _, l := range strings.Split(j, "\n") {
		if strings.Contains(l, key) && strings.Contains(l, name) && strings.Contains(l, want) && strings.Contains(l, "which a grant never opens") {
			return true
		}
	}
	return false
}

func labExpectOpen(t *testing.T, ctx context.Context, admin, name string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last string
	var code int
	for {
		last, code = labExec(ctx, admin, labEgressB, "probe", "python3", "-c", labTLS, name, name, "443", "20")
		if code == 0 && strings.Contains(last, "HTTP/") {
			t.Logf("%s:443: %s", name, oneLine(last))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s:443 did not answer (exit %d)\n%s", name, code, last)
		}
		time.Sleep(3 * time.Second)
	}
}

// labLoginAdmin invites user as admin of ns and signs in. The context name is the user.
func labLoginAdmin(t *testing.T, ctx context.Context, admin, user, ns string) string {
	t.Helper()
	inv := labKvoadm(t, ctx, filepath.Dir(os.Getenv("KVO_CONFIG")), "users", "invite", user, "--namespace", ns, "--role", "admin", "--context", admin)
	t.Logf("invite: %s", labRedact(inv))
	loginMatch := regexp.MustCompile(`kvo login (\S+) --ca (sha256:[0-9a-f]{64})`).FindStringSubmatch(inv)
	inviteMatch := regexp.MustCompile(`invite code: (kvi_\S+)`).FindStringSubmatch(inv)
	if loginMatch == nil || inviteMatch == nil {
		t.Fatalf("invite output had no login line: %s", labRedact(inv))
	}
	if !strings.Contains(inv, user+" is admin in namespace "+ns) {
		t.Fatalf("invite did not bind %s as admin in %s", user, ns)
	}
	saved := kvo.Browser
	kvo.Browser = func(authURL string) error { return labPlayBrowser(authURL, inviteMatch[1]) }
	defer func() { kvo.Browser = saved }()
	out := labKvo(t, ctx, "", "login", loginMatch[1], "--ca", loginMatch[2], "--context", user)
	t.Logf("login: %s", oneLine(labRedact(strings.ReplaceAll(out, inviteMatch[1], "[invite]"))))
	who := labKvo(t, ctx, "", "auth", "--context", user, "whoami")
	if !strings.Contains(who, "user "+user) {
		t.Fatalf("whoami: %s", who)
	}
	return user
}

// labSweep removes what a test created. A namespace delete waits until its silos are gone.
// Leftovers are logged; the lab is thrown away by lab-down.
func labSweep(ctx context.Context, t *testing.T, admin string, silos [][2]string, extras [][3]string, nss []string) {
	t.Helper()
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for _, s := range silos {
		labForget(t, cctx, "delete", "--context", admin, "silo", s[1], "-n", s[0])
	}
	deadline := time.Now().Add(2 * time.Minute)
	for _, s := range silos {
		for time.Now().Before(deadline) {
			out, code := labKvoCode(cctx, "", "get", "--context", admin, "silo", s[1], "-n", s[0])
			if code != 0 && strings.Contains(out, "NotFound") {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	for _, e := range extras {
		args := []string{"delete", "--context", admin, e[0], e[2]}
		if e[1] != "" {
			args = append(args, "-n", e[1])
		}
		labForget(t, cctx, args...)
	}
	for _, ns := range nss {
		labForget(t, cctx, "delete", "--context", admin, "namespace", ns)
	}
}

func labForget(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	out, code := labKvoCode(ctx, "", args...)
	if code != 0 && !strings.Contains(out, "NotFound") {
		t.Logf("cleanup %v: %s", args, oneLine(out))
	}
}
