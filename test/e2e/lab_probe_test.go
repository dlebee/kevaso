package e2e

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLabProbeScriptReadsPastTheHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	held := make(chan struct{})
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		close(accepted)
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"))
		time.Sleep(80 * time.Millisecond)
		_, _ = conn.Write([]byte("target 8080\n"))
		<-held
	}()

	script, err := labProbeScript(port, "target")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "-c", script).CombinedOutput()
	close(held)
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("the probe returned before the server accepted")
	}
	if !strings.Contains(string(out), "target 8080") {
		t.Fatalf("probe output: %s", out)
	}
}

func TestLabProbeScriptMissesABodyThatNeverArrives(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
			_ = conn.Close()
		}
	}()

	script, err := labProbeScript(port, "target")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "-c", script).CombinedOutput()
	if err == nil {
		t.Fatalf("headers without the body counted as ready: %s", out)
	}
	if strings.Contains(string(out), "target 8080") {
		t.Fatalf("probe invented the body: %s", out)
	}
}

func TestLabReadUntilReadsASplitStatusLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	held := make(chan struct{})
	defer close(held)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("HT"))
		time.Sleep(50 * time.Millisecond)
		_, _ = conn.Write([]byte("TP/1.0 200 OK\r\n\r\n"))
		<-held
	}()
	script := fmt.Sprintf("import socket, time, sys\ns = socket.create_connection((\"127.0.0.1\", %d), 2)\ntls = s\ntls.settimeout(0.2)\n%s", port, labReadUntil("HTTP/", 2))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("read: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "HTTP/") {
		t.Fatalf("read output: %s", out)
	}
}

func TestLabProbeScriptRejectsABadWant(t *testing.T) {
	if _, err := labProbeScript(8080, "not a silo"); err == nil {
		t.Fatal("a want with a space was accepted")
	}
	if _, err := labProbeScript(0, "target"); err == nil {
		t.Fatal("port 0 was accepted")
	}
	got := labReadUntil("HTTP/", 2)
	if !strings.Contains(got, `"HTTP/"`) || !strings.Contains(got, "tls.recv(180)") {
		t.Fatalf("read loop: %s", got)
	}
}
