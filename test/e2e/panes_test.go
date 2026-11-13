//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// TestPanes is design §10.1 on real machines (ADR 0009): a cloud-hypervisor silo with spec.panes
// runs a small pane server of its own (python3, nothing of Kevaso's) and its host fetches from it:
// a status pane and an HTML pane; kvo get panes and kvo pane watch show the status pane, and follow
// an update; kvo pane bundle -o FILE saves the HTML pane's bundle byte for byte; a silo without
// spec.panes, running the same server, is never fetched.
//
//	metal-1  control plane + worker with KVM (cloud-hypervisor) and docker
func TestPanes(t *testing.T) {
	r := newRig(t, 40*time.Minute, map[string]testbed.Spec{
		"metal": {Role: "metal", CPUs: 4, Memory: "4GiB", Disk: "30GiB", KVM: true, Shared: true},
	})
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "docker", "--loop-storage", "20G")...)
	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: ux }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: agent, namespace: ux }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
  panes: { http: { port: 7070, path: /panes }, every: 1s, allow: [status, html] }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: quiet, namespace: ux }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
`, "apply", "-f", "-")
	r.waitRunning("ux", 30*time.Minute, "metal", "agent", "quiet")
	// The silos' own software: the pane protocol's two GETs, from files the test writes.
	for _, s := range []string{"agent", "quiet"} {
		r.upload("ux", s, "/usr/local/bin/pane-server", []byte(paneServer))
		r.in("ux", s, "mkdir -p /srv/panes && printf '{\"panes\": []}' > /srv/panes/list.json && (setsid /usr/local/bin/pane-server >/var/log/pane-server.log 2>&1 &)")
	}
	report := func(silo, list string) {
		t.Helper()
		r.upload("ux", silo, "/srv/panes/list.json.new", []byte(list))
		if out, code := r.in("ux", silo, "mv /srv/panes/list.json.new /srv/panes/list.json"); code != 0 {
			t.Fatalf("pane list in %s: %d %s", silo, code, out)
		}
	}

	// kvo pane watch from before the first report: it follows what comes.
	wctx, stopWatch := context.WithCancel(r.ctx)
	var watched safeBuffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		kvo.Run(wctx, []string{"pane", "watch", "agent", "-n", "ux"}, nil, &watched, &watched)
	}()
	time.Sleep(2 * time.Second)

	// A status pane, with what a terminal must never get: an escape sequence in the message.
	report("agent", `{"panes": [{"pane": "build", "kind": "status", "state": "running", "progress": 0.4, "title": "Building the site",
		"message": "step 2 of 5\u001b[2J", "fields": [{"label": "commit", "value": "abc123"}], "ttl": "5m"}]}`)
	r.eventually("the host fetched the status pane", time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "get", "panes", "-n", "ux")
		return strings.Contains(out, "agent.build"), out
	})
	panes := r.must(kvo.Run, "", "get", "panes", "-n", "ux")
	t.Logf("kvo get panes:\n%s", panes)
	expect(t, "kvo get panes lists the status pane", panes, "agent.build")
	r.eventually("kvo pane watch shows the status pane", 30*time.Second, func() (bool, string) {
		s := watched.String()
		return strings.Contains(s, "ux/agent [build] running 40% Building the site · step 2 of 5") && strings.Contains(s, "commit=abc123"), s
	})
	if strings.Contains(watched.String(), "\x1b") {
		t.Errorf("an escape sequence reached the terminal: %q", watched.String())
	}
	// An update comes through the watch.
	report("agent", `{"panes": [{"pane": "build", "kind": "status", "state": "done", "progress": 1, "title": "Building the site", "ttl": "5m"}]}`)
	r.eventually("kvo pane watch follows the update", 30*time.Second, func() (bool, string) {
		s := watched.String()
		return strings.Contains(s, "[build] done 100%"), s
	})

	// An HTML pane: the bundle comes back byte for byte, never rendered or changed.
	bundle := []byte("<!doctype html><meta charset=utf-8><title>pane</title><script>document.body.textContent='hi ✓'</script>\n\x00\xff binary tail")
	sum := sha256.Sum256(bundle)
	digest := hex.EncodeToString(sum[:])
	r.upload("ux", "agent", "/srv/panes/"+digest, bundle)
	report("agent", `{"panes": [{"pane": "build", "kind": "status", "state": "done", "progress": 1, "title": "Building the site", "ttl": "5m"},
		{"pane": "preview", "kind": "html", "bundle": "sha256:`+digest+`", "data": {"visitors": 3}, "title": "Preview"}]}`)
	r.eventually("the host fetched the html pane", time.Minute, func() (bool, string) {
		out, _ := r.kvo("", "get", "panes", "-n", "ux")
		return strings.Contains(out, "agent.preview"), out
	})
	saved := filepath.Join(t.TempDir(), "bundle.html")
	r.must(kvo.Run, "", "pane", "bundle", "agent.preview", "-n", "ux", "-o", saved)
	got, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bundle) {
		t.Errorf("kvo pane bundle: %d bytes, want the %d uploaded", len(got), len(bundle))
	} else {
		t.Logf("kvo pane bundle saved the bundle byte for byte (sha256:%s)", hex.EncodeToString(sum[:])[:16])
	}
	expect(t, "kvo get panes lists the html pane", r.must(kvo.Run, "", "get", "panes", "-n", "ux"), "agent.preview")
	if out, code := r.kvo("", "pane", "bundle", "agent.build", "-n", "ux", "-o", saved+".2"); code == 0 {
		t.Errorf("a status pane's bundle: %q", out)
	}

	// A silo without spec.panes answers the same protocol, and is never asked.
	report("quiet", `{"panes": [{"pane": "build", "kind": "status", "state": "running"}]}`)
	time.Sleep(5 * time.Second)
	if strings.Contains(r.must(kvo.Run, "", "get", "panes", "-n", "ux"), "quiet.") {
		t.Error("a pane of the silo without spec.panes was fetched")
	}
	if out, _ := r.in("ux", "quiet", "cat /var/log/pane-server.log"); strings.Contains(out, "GET") {
		t.Errorf("the host asked a silo without spec.panes: %s", out)
	}
	// A silo that answers too much is cut off: its condition says why.
	report("agent", `{"panes": [{"pane": "build", "kind": "status", "message": "`+strings.Repeat("x", 400<<10)+`"}]}`)
	r.eventually("an oversized answer cuts the silo off", time.Minute, func() (bool, string) {
		s := r.silo("ux", "agent")
		for _, c := range s.Status.Conditions {
			if c.Type == "Panes" && c.Reason == "CutOff" {
				return true, c.Message
			}
		}
		return false, fmt.Sprint(s.Status.Conditions)
	})
	stopWatch()
	wg.Wait()
	t.Logf("kvo pane watch printed:\n%s", watched.String())
}

// safeBuffer is a buffer written by one goroutine and read by another.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// paneServer is what a silo runs to answer the pane protocol (ADR 0009): GET /panes is
// /srv/panes/list.json, GET /panes/bundles/sha256:HEX is /srv/panes/HEX.
const paneServer = `#!/usr/bin/env python3
import http.server, re
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        m = re.fullmatch(r"/panes/bundles/sha256:([0-9a-f]{64})", self.path)
        if self.path == "/panes":
            f, t = "/srv/panes/list.json", "application/json"
        elif m:
            f, t = "/srv/panes/" + m.group(1), "application/octet-stream"
        else:
            self.send_error(404); return
        try:
            b = open(f, "rb").read()
        except OSError:
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", t)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
http.server.ThreadingHTTPServer(("", 7070), H).serve_forever()
`
