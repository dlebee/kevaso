//go:build metal

package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
)

// These run on a worktree lab (LAB_NAME). They do not call metal(), so they do not reset the machine.

const (
	labCapNS  = "kcap"
	labCutNS  = "kcut"
	labDNSNS  = "kdns"
	labDiskNS = "kdisk"
)

func TestLabContainerDropsNetRaw(t *testing.T) {
	admin := labAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() { labSweep(ctx, t, admin, [][2]string{{labCapNS, "box"}}, nil, []string{labCapNS}) })
	labNamespace(t, ctx, admin, labCapNS)
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: box, namespace: %s }
spec:
  runtime: docker
  container: { image: docker.io/library/ubuntu:24.04, command: ["sleep", "infinity"] }
  resources: { cpu: 1, memory: 256Mi }
`, labCapNS), "apply", "--context", admin, "-f", "-")
	s := labWaitRunning(t, ctx, admin, labCapNS, "box", 15*time.Minute)
	gw := siloGateway(s.Status.SiloIP)
	out, code := labExec(ctx, admin, labCapNS, "box", "ping", "-c", "1", "-W", "2", gw)
	if code == 0 || !strings.Contains(strings.ToLower(out), "not permitted") {
		t.Fatalf("ping %s from a container: exit %d, want it refused (no NET_RAW)\n%s", gw, code, out)
	}
	t.Logf("ping %s: %s", gw, oneLine(out))
}

func siloGateway(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "10.64.0.1"
	}
	parts[3] = "1"
	return strings.Join(parts, ".")
}

func TestLabDeletingAGrantResetsItsConnection(t *testing.T) {
	admin := labAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() {
		labSweep(ctx, t, admin, [][2]string{{labCutNS, "probe"}}, [][3]string{
			{"grant", labCutNS, "cf1"}, {"grant", labCutNS, "cf2"},
		}, []string{labCutNS})
	})
	labNamespace(t, ctx, admin, labCutNS)
	for _, g := range []struct{ name, to string }{{"cf1", "1.1.1.1/32"}, {"cf2", "1.0.0.1/32"}} {
		labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Grant
metadata: { name: %s, namespace: %s }
spec:
  egress:
    - { to: %s, ports: ["443"] }
`, g.name, labCutNS, g.to), "apply", "--context", admin, "-f", "-")
	}
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: probe, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
  grants: [cf1, cf2]
`, labCutNS, labImage), "apply", "--context", admin, "-f", "-")
	labWaitRunning(t, ctx, admin, labCutNS, "probe", 15*time.Minute)
	hold := `import os, socket, sys, time
dest, path = sys.argv[1], sys.argv[2]
if os.fork() > 0:
    os._exit(0)
os.setsid()
try:
    s = socket.create_connection((dest, 443), 20)
except Exception as e:
    open(path, "w").write("connect " + type(e).__name__)
    os._exit(0)
open(path, "w").write("open")
try:
    while True:
        s.send(b"x")
        s.settimeout(1)
        try:
            s.recv(1)
        except socket.timeout:
            pass
        time.sleep(0.3)
except Exception as e:
    open(path, "w").write(type(e).__name__)
`
	if out, code := labExec(ctx, admin, labCutNS, "probe", "python3", "-c", hold, "1.1.1.1", "/tmp/cf1"); code != 0 {
		t.Fatalf("start 1.1.1.1: exit %d\n%s", code, out)
	}
	if out, code := labExec(ctx, admin, labCutNS, "probe", "python3", "-c", hold, "1.0.0.1", "/tmp/cf2"); code != 0 {
		t.Fatalf("start 1.0.0.1: exit %d\n%s", code, out)
	}
	waitFile := func(path, want string) string {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		var last string
		for {
			last, _ = labExec(ctx, admin, labCutNS, "probe", "cat", path)
			if strings.Contains(last, want) {
				return last
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never said %q, last %q", path, want, last)
			}
			time.Sleep(time.Second)
		}
	}
	waitFile("/tmp/cf1", "open")
	waitFile("/tmp/cf2", "open")
	labKvo(t, ctx, "", "delete", "--context", admin, "grant", "cf1", "-n", labCutNS)
	got := waitFile("/tmp/cf1", "ConnectionResetError")
	t.Logf("cf1 after the grant was deleted: %s", oneLine(got))
	time.Sleep(3 * time.Second)
	other, _ := labExec(ctx, admin, labCutNS, "probe", "cat", "/tmp/cf2")
	if strings.TrimSpace(other) != "open" {
		t.Fatalf("1.0.0.1's grant is still there and its connection changed: %q", other)
	}
}

func TestLabNoGrantSiloIsNotForwarded(t *testing.T) {
	admin := labAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() {
		labSweep(ctx, t, admin, [][2]string{{labDNSNS, "ask"}, {labDNSNS, "target"}}, nil, []string{labDNSNS})
	})
	labNamespace(t, ctx, admin, labDNSNS)
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: target, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
  ports: [{ name: http, port: 80 }]
`, labDNSNS, labImage), "apply", "--context", admin, "-f", "-")
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: ask, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
`, labDNSNS, labImage), "apply", "--context", admin, "-f", "-")
	target := labWaitRunning(t, ctx, admin, labDNSNS, "target", 15*time.Minute)
	labWaitRunning(t, ctx, admin, labDNSNS, "ask", 15*time.Minute)
	script := fmt.Sprintf(`import socket
def ask(name):
    try:
        return socket.getaddrinfo(name, 80)[0][4][0]
    except Exception as e:
        return "REFUSED " + type(e).__name__
print("out", ask("example.com"))
print("in", ask("target.%s.kevaso"))
`, labDNSNS)
	out, code := labExec(ctx, admin, labDNSNS, "ask", "python3", "-c", script)
	if code != 0 {
		t.Fatalf("resolve: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "out REFUSED") {
		t.Fatalf("example.com from a silo with no grant:\n%s", out)
	}
	if !strings.Contains(out, "in "+target.Status.SiloIP) {
		t.Fatalf("target.%s.kevaso: want %s\n%s", labDNSNS, target.Status.SiloIP, out)
	}
	t.Logf("dns:\n%s", out)
}

func TestLabOversizedDiskIsRefused(t *testing.T) {
	admin := labAdmin(t)
	if os.Getenv("KEVASO_METAL_KEY") == "" {
		t.Fatal("KEVASO_METAL_KEY comes from the lab env file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() { labSweep(ctx, t, admin, [][2]string{{labDiskNS, "disk"}}, nil, []string{labDiskNS}) })
	labNamespace(t, ctx, admin, labDiskNS)
	const sum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: disk, namespace: %s }
spec:
  runtime: cloud-hypervisor
  vm:
    disk: { url: https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img, sha256: %s }
  resources: { cpu: 1, memory: 512Mi }
  disk: { size: 1Mi }
`, labDiskNS, sum), "apply", "--context", admin, "-f", "-")
	deadline := time.Now().Add(10 * time.Minute)
	var host, last string
	var code int
	for {
		last, code = labKvoCode(ctx, "", "get", "--context", admin, "silo", "disk", "-n", labDiskNS, "-o", "json")
		if code == 0 && strings.Contains(last, "larger than the disk") {
			if s := labGetSilo(t, ctx, admin, labDiskNS, "disk"); s.Status.Host != "" {
				host = s.Status.Host
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the oversized disk was not refused:\n%s", last)
		}
		time.Sleep(2 * time.Second)
	}
	if host == "" {
		t.Fatal("the silo was refused and has no host to check the partial file on")
	}
	node := labDial(t, ctx, labGetHost(t, ctx, admin, host), os.Getenv("KEVASO_METAL_KEY"))
	t.Cleanup(func() { _ = node.d.Close() })
	partial := cloudhypervisor.ImagesDir + "/sha256-" + sum + ".img.download"
	final := cloudhypervisor.ImagesDir + "/sha256-" + sum + ".img"
	gone := time.Now().Add(30 * time.Second)
	var saw string
	for {
		saw = node.must("if test -e " + partial + "; then echo partial; elif test -e " + final + "; then echo final; else echo gone; fi")
		if strings.TrimSpace(saw) == "gone" {
			t.Logf("partial file gone: %s", partial)
			return
		}
		if time.Now().After(gone) {
			t.Fatalf("the fetch left %s (%s)", partial, strings.TrimSpace(saw))
		}
		time.Sleep(time.Second)
	}
}
