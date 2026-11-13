//go:build e2e

package e2e

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// bannerPy answers "hello" on the debug port, then echoes each line back; and "web answers" on
// the web port.
const bannerPy = `import socket, sys, threading
def debug(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", p)); s.listen()
    while True:
        c, _ = s.accept()
        def serve(c):
            c.sendall(b"hello\n"); f = c.makefile("rb")
            for line in f: c.sendall(line)
            c.close()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
def web(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", p)); s.listen()
    while True:
        c, _ = s.accept(); c.sendall(b"web answers\n"); c.close()
threading.Thread(target=web, args=(int(sys.argv[1]),), daemon=True).start()
debug(int(sys.argv[2]))
`

// forward is an SSH forward from the Mac's loopback, through a machine, to addr: a connection to
// the returned address is one from that machine to addr (Lima's shared network isn't routed to
// the Mac). It stops with the test.
func (r *rig) forward(via, addr string) string {
	r.t.Helper()
	info, err := r.sshd.SSH(r.ctx, r.machines[via])
	if err != nil {
		r.t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	local := l.Addr().String()
	_ = l.Close()
	cmd := exec.CommandContext(r.ctx, "ssh", "-N", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ExitOnForwardFailure=yes", "-o", "LogLevel=ERROR", "-i", info.KeyFile, "-p", strconv.Itoa(info.Port),
		"-L", local+":"+addr, info.User+"@"+info.Host)
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for i := 0; i < 50; i++ {
		if c, err := net.DialTimeout("tcp", local, time.Second); err == nil {
			_ = c.Close()
			return local
		}
		time.Sleep(200 * time.Millisecond)
	}
	r.t.Fatalf("ssh -L %s:%s through %s never listened", local, addr, via)
	return ""
}

// banner reads the first line a port says, or "".
func banner(addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	return bufio.NewReader(c).ReadString('\n')
}

// portScript is what a silo runs to open or close one of its leased ports on its local endpoint
// (ADR 0009): it asks again with the approval's name while the answer is 428 (waiting for a yes),
// prints the last status and body, and fails unless it was 200.
func portScript(port, op, query string) string {
	return fmt.Sprintf(`u='http://169.254.42.1/v1/ports/%s/%s%s'; a=
while :; do
  code=$(curl -sS -o /tmp/answer -w '%%{http_code}' -X POST -H 'Kevaso-Local: 1' "$u${a:+&approval=$a}")
  [ "$code" = 428 ] || break
  a=$(sed -n 's/.*"name":"\([^"]*\)".*/\1/p' /tmp/answer); sleep 2
done
echo "$code $(cat /tmp/answer)"; [ "$code" = 200 ]`, port, op, query)
}

// leaseOf reads one silo port's lease ("" phase: none).
func (r *rig) leaseOf(ns, silo, port string) v1.Lease {
	r.t.Helper()
	out, _ := r.kvo("", "get", "leases", "-n", ns, "-o", "json")
	for _, raw := range jsonItems(out) {
		var l v1.Lease
		if json.Unmarshal(raw, &l) == nil && l.Spec.Silo == silo && l.Spec.Port == port {
			return l
		}
	}
	return v1.Lease{}
}

// TestVMLeases is design §7.2d on cloud-hypervisor silos, the address DNATed to a VM on the host's
// bridge: a leased hostPort port is closed by default; the guest opens it itself (POST
// /v1/ports/NAME/open on its local endpoint, 169.254.42.1), with and without approval: required; from the Mac
// (through an SSH forward on a second machine, so the traffic arrives on the host's address like
// a client's) it answers while the lease lasts, a held connection is cut at its end and new ones
// are refused; the unleased port answers throughout.
//
//	metal   control plane + worker with KVM (cloud-hypervisor)
//	client  the machine the Mac's connections leave from
func TestVMLeases(t *testing.T) {
	r := newRig(t, 50*time.Minute, map[string]testbed.Spec{
		"metal":  {Role: "metal", CPUs: 4, Memory: "4GiB", Disk: "30GiB", KVM: true, Shared: true},
		"client": {Role: "client", CPUs: 1, Memory: "1GiB", Disk: "10GiB", Shared: true},
	})
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--loop-storage", "20G")...)
	b64 := base64.StdEncoding.EncodeToString([]byte(bannerPy))
	silo := func(name, lease string, web, debug int) string {
		return fmt.Sprintf(`---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: lz }
spec:
  runtime: cloud-hypervisor
  vm: { image: ubuntu-24.04 }
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  init:
    steps:
      - name: banner
        run: echo %s | base64 -d > /usr/local/bin/banner.py && systemd-run --unit=banner python3 /usr/local/bin/banner.py %d %d
  ports: [{ name: web, port: %d }, { name: debug, port: %d }]
  service:
    ports:
      - { port: web, hostPort: [internal] }
      - { port: debug, hostPort: [internal], lease: %s }
`, name, b64, web, debug, web, debug, lease)
	}
	r.must(kvo.Run, "apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: lz }\n"+
		silo("api", "{ max: 2m }", 8080, 9229)+
		silo("gated", "{ max: 5m, approval: { required: true } }", 8081, 9230), "apply", "-f", "-")
	r.waitRunning("lz", 30*time.Minute, "metal", "api", "gated")
	addr := map[string]string{"api": r.forward("client", metalIP+":9229"), "gated": r.forward("client", metalIP+":9230")}
	web := map[string]string{"api": r.forward("client", metalIP+":8080"), "gated": r.forward("client", metalIP+":8081")}

	isOpen := func(name string) (bool, string) {
		got, err := banner(addr[name])
		return got == "hello\n", fmt.Sprintf("%q %v", got, err)
	}
	webUp := func(when string) {
		t.Helper()
		for _, name := range []string{"api", "gated"} {
			ok := false
			var got string
			for i := 0; i < 10 && !ok; i++ {
				got, _ = banner(web[name])
				if ok = got == "web answers\n"; !ok {
					time.Sleep(2 * time.Second)
				}
			}
			if !ok {
				t.Fatalf("%s: %s's web port: %q", when, name, got)
			}
		}
	}
	staysClosed := func(name, when string, d time.Duration) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(2 * time.Second) {
			if ok, s := isOpen(name); ok {
				t.Fatalf("%s: %s's debug port answered: %s", when, name, s)
			}
		}
		t.Logf("%s: %s's debug port closed", when, name)
	}
	opens := func(name, when string) {
		t.Helper()
		if !r.eventually(when+": "+name+"'s debug port open from the Mac", 45*time.Second, func() (bool, string) { return isOpen(name) }) {
			rules, _ := r.sh("metal", "nft list ruleset | grep -n -i -e 9229 -e 9230 -e lease")
			t.Fatalf("rules:\n%s\n%s", rules, r.journal("metal", 30))
		}
	}

	// The debug ports are closed by default; the web ports aren't leased.
	webUp("at first")
	staysClosed("api", "closed by default", 6*time.Second)
	staysClosed("gated", "closed by default", 6*time.Second)

	// From inside the VM, no approval: endpoint ports/debug/open --for 60s.
	out, code := r.in("lz", "api", portScript("debug", "open", "?for=60s"))
	t.Logf("endpoint ports/debug/open debug --for 60s: %d %s", code, out)
	if code != 0 {
		t.Fatalf("endpoint ports/debug/open: exit %d", code)
	}
	opens("api", "endpoint ports/debug/open --for 60s")
	l := r.leaseOf("lz", "api", "debug")
	if l.Status.Phase != v1.LeaseOpen || l.Status.Until == nil {
		t.Fatalf("lease: %+v", l.Status)
	}
	t.Logf("lease %s: open until %s, asked by %s", l.Name, l.Status.Until.Format(time.TimeOnly), l.Status.RequestedBy)
	until := *l.Status.Until
	conn, err := net.DialTimeout("tcp", addr["api"], 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if hello, err := rd.ReadString('\n'); hello != "hello\n" {
		t.Fatalf("held connection: %q %v", hello, err)
	}
	var cut time.Time
	for i := 0; time.Now().Before(until.Add(45 * time.Second)); i++ {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		msg := fmt.Sprintf("ping %d\n", i)
		_, werr := conn.Write([]byte(msg))
		got, rerr := rd.ReadString('\n')
		if werr != nil || rerr != nil || got != msg {
			cut = time.Now()
			t.Logf("held connection cut %s after the lease's end (%v %v %q)", cut.Sub(until).Round(time.Second), werr, rerr, got)
			break
		}
		time.Sleep(time.Second)
	}
	_ = conn.Close()
	switch {
	case cut.IsZero():
		t.Errorf("a connection held open still worked 45s after the lease ended at %s", until.Format(time.TimeOnly))
	case cut.Before(until.Add(-3 * time.Second)):
		t.Errorf("the connection was cut at %s, before the lease's end at %s", cut.Format(time.TimeOnly), until.Format(time.TimeOnly))
	}
	r.eventually("after its end, api's debug port closed", 20*time.Second, func() (bool, string) {
		ok, s := isOpen("api")
		return !ok, s
	})
	staysClosed("api", "after its end", 6*time.Second)
	webUp("after the lease ended")
	if l := r.leaseOf("lz", "api", "debug"); l.Status.Phase != v1.LeaseClosed {
		t.Errorf("after its end: %+v", l.Status)
	}

	// The guest closes its own lease early.
	if out, code := r.in("lz", "api", portScript("debug", "open", "?for=2m")); code != 0 {
		t.Fatalf("endpoint ports/debug/open --for 2m: %d %s", code, out)
	}
	opens("api", "endpoint ports/debug/open --for 2m")
	if out, code := r.in("lz", "api", portScript("debug", "close", "?")); code != 0 {
		t.Fatalf("endpoint ports/debug/close: %d %s", code, out)
	}
	r.eventually("endpoint ports/debug/close: closed", 20*time.Second, func() (bool, string) {
		ok, s := isOpen("api")
		return !ok, s
	})

	// approval: required. The guest's ask waits (--wait) while the port stays closed, until a
	// person's yes; then it's open; a no keeps it closed.
	type res struct {
		out  string
		code int
	}
	done := make(chan res, 1)
	go func() {
		out, code := r.in("lz", "gated", portScript("debug", "open", "?for=60s&wait=3m"))
		done <- res{out, code}
	}()
	var pending string
	r.eventually("gated's own ask is pending", 45*time.Second, func() (bool, string) {
		l := r.leaseOf("lz", "gated", "debug")
		if l.Status.Pending != nil {
			pending = l.Status.Pending.Approval
		}
		return pending != "", fmt.Sprintf("%+v", l.Status)
	})
	appr, _ := r.kvo("", "get", "approvals", "-n", "lz")
	t.Logf("kvo get approvals:\n%s", appr)
	staysClosed("gated", "its ask waiting for a yes", 8*time.Second)
	r.must(kvo.Run, "", "approve", pending, "-n", "lz")
	select {
	case res := <-done:
		t.Logf("endpoint ports/debug/open --wait after the yes: %d %s", res.code, res.out)
		if res.code != 0 {
			t.Errorf("endpoint ports/debug/open --wait: exit %d", res.code)
		}
	case <-time.After(90 * time.Second):
		t.Error("endpoint ports/debug/open --wait didn't return after the yes")
	}
	opens("gated", "approved")
	if l := r.leaseOf("lz", "gated", "debug"); l.Status.ApprovedBy == "" || l.Status.Phase != v1.LeaseOpen {
		t.Errorf("approved lease: %+v", l.Status)
	}
	if out, code := r.in("lz", "gated", portScript("debug", "close", "?")); code != 0 {
		t.Fatalf("close: %d %s", code, out)
	}
	r.eventually("gated closed again", 20*time.Second, func() (bool, string) {
		ok, s := isOpen("gated")
		return !ok, s
	})
	go func() {
		out, code := r.in("lz", "gated", portScript("debug", "open", "?for=60s&wait=2m"))
		done <- res{out, code}
	}()
	pending = ""
	r.eventually("gated's second ask is pending", 45*time.Second, func() (bool, string) {
		l := r.leaseOf("lz", "gated", "debug")
		if l.Status.Pending != nil {
			pending = l.Status.Pending.Approval
		}
		return pending != "", fmt.Sprintf("%+v", l.Status)
	})
	r.must(kvo.Run, "", "deny", pending, "-n", "lz", "--reason", "not now")
	select {
	case res := <-done:
		t.Logf("endpoint ports/debug/open after a no: %d %s", res.code, res.out)
		if res.code == 0 || !strings.Contains(res.out, "not now") {
			t.Errorf("a denied ask: exit %d %q", res.code, res.out)
		}
	case <-time.After(90 * time.Second):
		t.Error("endpoint ports/debug/open --wait didn't return after the no")
	}
	staysClosed("gated", "denied", 8*time.Second)
	if l := r.leaseOf("lz", "gated", "debug"); l.Status.Phase != v1.LeaseDenied {
		t.Errorf("denied lease: %+v", l.Status)
	}
	webUp("at the end")
	leases, _ := r.kvo("", "get", "leases", "-n", "lz")
	t.Logf("kvo get leases:\n%s", leases)
}
