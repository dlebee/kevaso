//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// TestPanes is design §10.1 on real machines: a cloud-hypervisor silo with spec.panes reports a
// status pane and an HTML pane over its own broker channel (vsock); kvo get panes and
// kvo pane watch show the status pane, and follow an update; kvo pane bundle -o FILE saves the HTML
// pane's bundle byte for byte; a silo without spec.panes is refused, saying why.
//
//	metal-1  control plane + worker with KVM (cloud-hypervisor) and docker
func TestPanes(t *testing.T) {
	r := newRig(t, 40*time.Minute, map[string]testbed.Spec{
		"metal": {Role: "metal", CPUs: 4, Memory: "4GiB", Disk: "30GiB", KVM: true, Shared: true},
	})
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--internal-ip", metalIP, "--worker",
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
  panes: { enabled: true, allow: [status, html] }
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
	out, code := r.in("ux", "agent", `kvo-guest pane report build --state running --progress 0.4 --title 'Building the site' --message "$(printf 'step 2 of 5\033[2J')" --field 'commit=abc123' --ttl 5m`)
	if code != 0 || out != "ok" {
		t.Fatalf("pane report: %d %q", code, out)
	}
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
	if out, code := r.in("ux", "agent", "kvo-guest pane report build --state done --progress 1 --title 'Building the site'"); code != 0 || out != "ok" {
		t.Fatalf("pane update: %d %q", code, out)
	}
	r.eventually("kvo pane watch follows the update", 30*time.Second, func() (bool, string) {
		s := watched.String()
		return strings.Contains(s, "[build] done 100%"), s
	})

	// An HTML pane: the bundle comes back byte for byte, never rendered or changed.
	bundle := []byte("<!doctype html><meta charset=utf-8><title>pane</title><script>document.body.textContent='hi ✓'</script>\n\x00\xff binary tail")
	r.upload("ux", "agent", "/tmp/pane.html", bundle)
	if out, code := r.in("ux", "agent", `kvo-guest pane html preview --bundle /tmp/pane.html --data '{"visitors": 3}' --title Preview`); code != 0 || out != "ok" {
		t.Fatalf("pane html: %d %q", code, out)
	}
	saved := filepath.Join(t.TempDir(), "bundle.html")
	r.must(kvo.Run, "", "pane", "bundle", "agent.preview", "-n", "ux", "-o", saved)
	got, err := os.ReadFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundle)
	if !bytes.Equal(got, bundle) {
		t.Errorf("kvo pane bundle: %d bytes, want the %d uploaded", len(got), len(bundle))
	} else {
		t.Logf("kvo pane bundle saved the bundle byte for byte (sha256:%s)", hex.EncodeToString(sum[:])[:16])
	}
	expect(t, "kvo get panes lists the html pane", r.must(kvo.Run, "", "get", "panes", "-n", "ux"), "agent.preview")
	if out, code := r.kvo("", "pane", "bundle", "agent.build", "-n", "ux", "-o", saved+".2"); code == 0 {
		t.Errorf("a status pane's bundle: %q", out)
	}

	// A silo without spec.panes is refused, saying why, and nothing is kept.
	out, code = r.in("ux", "quiet", "kvo-guest pane report build --state running")
	if code == 0 || !strings.Contains(out, "panes are off for this silo") {
		t.Errorf("a silo without spec.panes: exit %d %q", code, out)
	} else {
		t.Logf("a silo without spec.panes: %s", out)
	}
	if strings.Contains(r.must(kvo.Run, "", "get", "panes", "-n", "ux"), "quiet.") {
		t.Error("a pane of the silo without spec.panes was kept")
	}
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
