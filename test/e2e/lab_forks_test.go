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
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
`, labCapNS, labImage), "apply", "--context", admin, "-f", "-")
	s := labWaitRunning(t, ctx, admin, labCapNS, "box", 15*time.Minute)
	_ = s
	// A raw ICMP socket is what ping opens; without NET_RAW the kernel refuses it.
	raw := "import socket\ntry:\n    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)\n    print('opened')\nexcept PermissionError as e:\n    print('refused', e)"
	out, code := labExec(ctx, admin, labCapNS, "box", "python3", "-c", raw)
	if code != 0 || !strings.Contains(out, "refused") {
		t.Fatalf("a raw socket in a container: exit %d, want it refused (no NET_RAW)\n%s", code, out)
	}
	t.Logf("raw socket: %s", oneLine(out))
}

func siloGateway(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "10.64.0.1"
	}
	parts[3] = "1"
	return strings.Join(parts, ".")
}

func TestLabRemovingAllowFromResetsItsConnection(t *testing.T) {
	admin := labAdmin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(func() {
		labSweep(ctx, t, admin, [][2]string{{labCutNS, "target"}, {labCutNS, "caller"}, {labCutNS, "other"}}, nil, []string{labCutNS})
	})
	labNamespace(t, ctx, admin, labCutNS)
	targetSpec := func(allow string) string {
		return boxEcho(labCutNS, "target", labListenPort) + fmt.Sprintf(`  ports: [{ name: http, port: %d }]
  services:
    - ports: [{ port: http, allowFrom: [%s] }]
`, labListenPort, allow)
	}
	labKvo(t, ctx, targetSpec("caller, other"), "apply", "--context", admin, "-f", "-")
	for _, name := range []string{"caller", "other"} {
		labKvo(t, ctx, fmt.Sprintf(`apiVersion: kevaso/v1
kind: Silo
metadata: { name: %s, namespace: %s }
spec:
  runtime: docker
  container: { image: %s, command: ["python3", "-c", "import time; time.sleep(10**9)"] }
  resources: { cpu: 1, memory: 256Mi }
`, name, labCutNS, labImage), "apply", "--context", admin, "-f", "-")
	}
	target := labWaitRunning(t, ctx, admin, labCutNS, "target", 15*time.Minute)
	labWaitRunning(t, ctx, admin, labCutNS, "caller", 15*time.Minute)
	labWaitRunning(t, ctx, admin, labCutNS, "other", 15*time.Minute)
	if heard := labAwaitListen(t, ctx, admin, labCutNS, "target"); !strings.Contains(heard, "target") {
		t.Fatalf("target listening on %d: %s", labListenPort, heard)
	}
	hold := `import os, socket, sys, time
dest, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
if os.fork() > 0:
    os._exit(0)
os.setsid()
try:
    s = socket.create_connection((dest, port), 20)
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
	start := func(name string) {
		t.Helper()
		if out, code := labExec(ctx, admin, labCutNS, name, "python3", "-c", hold, target.Status.SiloIP, fmt.Sprint(labListenPort), "/tmp/hold"); code != 0 {
			t.Fatalf("start %s: exit %d\n%s", name, code, out)
		}
	}
	start("caller")
	start("other")
	waitFile := func(silo, path, want string) string {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		var last string
		for {
			last, _ = labExec(ctx, admin, labCutNS, silo, "cat", path)
			if strings.Contains(last, want) {
				return last
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s %s never said %q, last %q", silo, path, want, last)
			}
			time.Sleep(time.Second)
		}
	}
	waitFile("caller", "/tmp/hold", "open")
	waitFile("other", "/tmp/hold", "open")
	labKvo(t, ctx, targetSpec("other"), "apply", "--context", admin, "-f", "-")
	got := waitFile("caller", "/tmp/hold", "ConnectionResetError")
	t.Logf("caller after allowFrom dropped it: %s", oneLine(got))
	time.Sleep(3 * time.Second)
	kept, _ := labExec(ctx, admin, labCutNS, "other", "cat", "/tmp/hold")
	if strings.TrimSpace(kept) != "open" {
		t.Fatalf("other is still named in allowFrom and its connection changed: %q", kept)
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
  services:
    - ports: [{ port: http }]
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
        return "REFUSED " + type(e).__name__ + " " + str(e)
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
