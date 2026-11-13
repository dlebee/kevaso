//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
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

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// echo.py answers on the ports it's given with "NAME sees ADDRESS": the caller's address as the
// silo saw it (so the test can tell the client IP was kept).
const echoPy = `import socket, sys, threading, os
name = os.uname().nodename
def tcp(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", p)); s.listen()
    while True:
        c, a = s.accept(); c.sendall(f"{name} sees {a[0]}\n".encode()); c.close()
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", p))
    while True:
        d, a = s.recvfrom(100); s.sendto(f"{name} sees {a[0]}\n".encode(), a)
for spec in sys.argv[1:]:
    proto, port = spec.split("/")
    threading.Thread(target=tcp if proto == "tcp" else udp, args=(int(port),), daemon=True).start()
threading.Event().wait()
`

func echoInit(ports ...string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(echoPy))
	return fmt.Sprintf(`
  init:
    steps:
      - name: echo
        run: echo %s | base64 -d > /usr/local/bin/echo.py && systemd-run --unit=echo python3 /usr/local/bin/echo.py %s`, b64, strings.Join(ports, " "))
}

// TestServicesAndExposure is M6's "done when": examples 03 (hostPort: raw TCP+UDP on the host's
// address, the client's IP kept, a private port that stays private, a source-restricted port,
// outbound from the same IP) and 06 (ip-pool: metal-1's extra addresses, one IP per silo on the
// same port, in and out), plus default-deny between silos opened by allowFrom, and private names.
//
//	metal-1  control plane + KVM worker (one host), shared network
//	client   "the internet": another machine on the same network
func TestServicesAndExposure(t *testing.T) {
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
		"metal":  {Role: "metal", CPUs: 8, Memory: "8GiB", Disk: "60GiB", KVM: true, Shared: true},
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
	// Two unused addresses on the shared network for the IPPool (the DHCP range starts low), fresh
	// for each run.
	base := metalIP[:strings.LastIndex(metalIP, ".")+1]
	n := 150 + int(time.Now().Unix()%50)*2
	pool1, pool2 := base+strconv.Itoa(n), base+strconv.Itoa(n+1)
	t.Logf("metal-1 %s, client %s, pool %s %s", metalIP, clientIP, pool1, pool2)

	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
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
	hk, _ := d.Exec(ctx, machines["metal"], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	must(kvoadm.Run, "", "init", info.User+"@"+info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", strings.Fields(hk)[1], "--kevasod", bin, "--name", "metal-1", "--cluster", "e2e",
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker", "--loop-storage", "40G")
	// The two extra addresses routed to metal-1, for ip-pool to hand out.
	must(kvoadm.Run, "", "host", "addresses", "metal-1", "add", pool1, pool2)

	silo := func(ns, name, spec string) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
%s
`, name, ns, spec)
	}
	manifest := `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: web3 }
---
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: ops }
---
# M7: silos reach nothing outside the cluster without a grant; these open the client's port 9100,
# where the test listens to see which address a silo's traffic leaves from.
apiVersion: kevaso/v1
kind: Grant
metadata: { name: to-client, namespace: web3 }
spec:
  egress: [{ to: "` + clientIP + `/32", ports: ["9100"] }]
` +
		// Example 03's P2P node: TCP+UDP 30303 public, rpc private, outbound from the same IP;
		// and rpc open to one other silo.
		silo("web3", "eth-node", `  service:
    ports:
      - { name: p2p,  port: 30303, protocol: TCP }
      - { name: disc, port: 30303, protocol: UDP }
      - { name: rpc,  port: 8545,  protocol: TCP }
    expose: hostPort
    hostPort: { ports: [p2p, disc] }
  network: { egress: { source: sameAsService } }
  grants: [to-client]
  allowFrom: [{ silo: ops/metrics, ports: [rpc] }]`+echoInit("tcp/30303", "udp/30303", "tcp/8545")) +
		// Example 03's dashboard, open to the client's address only…
		silo("ops", "metrics", `  service:
    ports: [{ name: web, port: 3000 }]
    expose: hostPort
    hostPort: { ports: [web], allowFrom: ["`+clientIP+`/32"] }`+echoInit("tcp/3000")) +
		// …and one open only to a range the client isn't in.
		silo("ops", "locked", `  service:
    ports: [{ name: web, port: 3001 }]
    expose: hostPort
    hostPort: { ports: [web], allowFrom: ["203.0.113.0/24"] }`+echoInit("tcp/3001")) +
		// Example 06: both on 30303, each on an IP of its own from metal-1's addresses, in and out.
		silo("web3", "eth-node-a", `  service:
    ports: [{ name: p2p, port: 30303, protocol: TCP }, { name: disc, port: 30303, protocol: UDP }]
    expose: loadBalancer
    loadBalancer: { class: ip-pool }
  network: { egress: { source: sameAsService } }
  grants: [to-client]`+echoInit("tcp/30303", "udp/30303")) +
		silo("web3", "eth-node-b", `  service:
    ports: [{ name: p2p, port: 30303, protocol: TCP }, { name: disc, port: 30303, protocol: UDP }]
    expose: loadBalancer
    loadBalancer: { class: ip-pool }
  network: { egress: { source: sameAsService } }`+echoInit("tcp/30303", "udp/30303"))
	must(kvo.Run, manifest, "apply", "-f", "-")

	// Wait for all five.
	deadline := time.Now().Add(30 * time.Minute)
	for {
		out := must(kvo.Run, "", "get", "silos", "-A")
		if strings.Count(out, "Running") == 5 {
			t.Logf("silos:\n%s", out)
			break
		}
		if time.Now().After(deadline) || strings.Contains(out, "Failed") {
			j, _ := sh("metal", "journalctl -u kevasod -n 50 --no-pager")
			t.Fatalf("silos:\n%s\nkevasod:\n%s", out, j)
		}
		time.Sleep(10 * time.Second)
	}
	describe := must(kvo.Run, "", "describe", "silo", "eth-node-a", "-n", "web3")
	t.Logf("describe eth-node-a:\n%s", describe)
	if !strings.Contains(describe, pool1) && !strings.Contains(describe, pool2) {
		t.Fatalf("eth-node-a has no pool address:\n%s", describe)
	}

	probe := func(target string) string { // from the client, "the internet"
		var out string
		for attempt := 0; attempt < 6; attempt++ {
			out, _ = sh("client", target)
			if strings.Contains(out, "sees") {
				break
			}
			time.Sleep(2 * time.Second)
		}
		return strings.TrimSpace(out)
	}
	tcp := func(addr string, port int) string { return probe(fmt.Sprintf("nc -w3 %s %d </dev/null", addr, port)) }
	udp := func(addr string, port int) string { return probe(fmt.Sprintf("echo x | nc -u -w3 %s %d", addr, port)) }
	expect := func(what, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want %q", what, got, want)
		} else {
			t.Logf("%s: %s", what, got)
		}
	}
	refused := func(what, got string) {
		t.Helper()
		if strings.Contains(got, "sees") {
			t.Errorf("%s should be closed, but answered %q", what, got)
		} else {
			t.Logf("%s: closed", what)
		}
	}

	// 03: TCP and UDP 30303 on metal-1's address, the client's own IP seen inside.
	expect("hostPort TCP", tcp(metalIP, 30303), "eth-node sees "+clientIP)
	expect("hostPort UDP", udp(metalIP, 30303), "eth-node sees "+clientIP)
	refused("rpc (private)", tcp(metalIP, 8545))
	expect("dashboard from the allowed address", tcp(metalIP, 3000), "metrics sees "+clientIP)
	refused("dashboard limited to 203.0.113.0/24", tcp(metalIP, 3001))

	// 06: same port, own addresses.
	a, b := tcp(pool1, 30303), tcp(pool2, 30303)
	if !(strings.Contains(a, "eth-node-a") && strings.Contains(b, "eth-node-b")) && !(strings.Contains(a, "eth-node-b") && strings.Contains(b, "eth-node-a")) {
		t.Errorf("pool addresses: %s → %q, %s → %q", pool1, a, pool2, b)
	}
	expect("pool UDP", udp(pool1, 30303), "sees "+clientIP)

	// Outbound: where does each silo's traffic come from? The client listens and reports.
	egressSeen := func(ns, silo string) string {
		_, _ = sh("client", `systemctl stop egress-listen 2>/dev/null; rm -f /tmp/egress; systemd-run --unit=egress-listen -p RuntimeMaxSec=30 python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 9100)); s.listen(); c, a = s.accept(); open("/tmp/egress", "w").write("from " + a[0] + "\n")'; sleep 1`)
		var e bytes.Buffer
		kvo.Run(ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", "echo hi | nc -w2 " + clientIP + " 9100"}, nil, io.Discard, &e)
		time.Sleep(time.Second)
		out, _ := sh("client", "cat /tmp/egress")
		return out
	}
	expect("eth-node's outbound (sameAsService)", egressSeen("web3", "eth-node"), metalIP)
	aIP := pool1
	if strings.Contains(a, "eth-node-b") {
		aIP = pool2
	}
	expect("eth-node-a's outbound (its pool address)", egressSeen("web3", "eth-node-a"), aIP)

	// Between silos: denied by default, opened by allowFrom; private names resolve.
	inside := func(ns, silo, script string) string {
		var o bytes.Buffer
		kvo.Run(ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", script}, nil, &o, io.Discard)
		return strings.TrimSpace(o.String())
	}
	expect("private name", inside("ops", "metrics", "getent hosts eth-node.web3.kevaso"), "eth-node.web3.kevaso")
	expect("metrics → eth-node rpc (allowFrom)", inside("ops", "metrics", "nc -w3 eth-node.web3.kevaso 8545 </dev/null"), "eth-node sees")
	refused("locked → eth-node rpc (not allowed)", inside("ops", "locked", "nc -w3 eth-node.web3.kevaso 8545 </dev/null"))
	refused("metrics → eth-node p2p (only rpc was allowed)", inside("ops", "metrics", "nc -w3 eth-node.web3.kevaso 30303 </dev/null"))
	refused("silo → its host's kevasod API", inside("ops", "metrics", "nc -w3 "+metalIP+" 6443 </dev/null && echo sees"))
	if out := egressSeen("ops", "metrics"); strings.Contains(out, "from") {
		t.Errorf("a silo without a grant reached the client (M7: default-deny egress): %q", out)
	} else {
		t.Log("silo without a grant → the client: refused")
	}
	expect("names still resolve without a grant (DNS on the gateway)", inside("ops", "metrics", "getent hosts ubuntu.com && echo sees"), "sees")
}
