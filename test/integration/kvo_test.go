// Package integration runs real components together in one process, with nothing faked but the
// clock: here, `kvo` against the API server over HTTP, on the in-memory store (M1's "done when").
package integration

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
)

const manifest = `
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: demo }
---
apiVersion: kevaso/v1
kind: Host
metadata: { name: hv1 }
spec:
  address: 203.0.113.10
  components:
    controlPlane: {}
    worker:
      labels: { region: ca-central }
      runtimes: [{ name: cloud-hypervisor }]
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: hello, namespace: demo }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 2, memory: 4Gi }
`

type harness struct {
	t      *testing.T
	server string
}

func newHarness(t *testing.T) *harness {
	srv, err := apiserver.New(store.NewMemory(0), clock.Real{})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &harness{t: t, server: ts.URL}
}

// kvo runs one command; it returns stdout, stderr and the exit code.
func (h *harness) kvo(ctx context.Context, stdin string, args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	args = append([]string{args[0], "--server", h.server}, args[1:]...) // before any `--`
	code := kvo.Run(ctx, args, strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

func (h *harness) ok(stdin string, args ...string) string {
	h.t.Helper()
	out, errs, code := h.kvo(context.Background(), stdin, args...)
	if code != 0 {
		h.t.Fatalf("kvo %s: exit %d: %s", strings.Join(args, " "), code, errs)
	}
	return out
}

func TestKvoAgainstAnInProcessServer(t *testing.T) {
	h := newHarness(t)

	// apply creates everything in the file.
	out := h.ok(manifest, "apply", "-f", "-")
	for _, want := range []string{"namespace/demo created", "host/hv1 created", "silo/hello created"} {
		if !strings.Contains(out, want) {
			t.Fatalf("apply output missing %q:\n%s", want, out)
		}
	}

	// get shows them as tables.
	if out := h.ok("", "get", "silos", "-n", "demo"); !strings.Contains(out, "hello") || !strings.Contains(out, "cloud-hypervisor") {
		t.Fatalf("get silos:\n%s", out)
	}
	if out := h.ok("", "get", "hosts"); !strings.Contains(out, "control-plane,worker") || !strings.Contains(out, "203.0.113.10") {
		t.Fatalf("get hosts:\n%s", out)
	}

	// A watch started now sees the next change.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wout string
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		wout, _, _ = h.kvo(ctx, "", "watch", "silos", "-n", "demo")
	}()
	time.Sleep(200 * time.Millisecond) // let the watch subscribe

	// apply again with a spec change updates it in place.
	changed := strings.Replace(manifest, "cpu: 2", "cpu: 4", 1)
	if out := h.ok(changed, "apply", "-f", "-"); !strings.Contains(out, "silo/hello configured") {
		t.Fatalf("second apply:\n%s", out)
	}
	if out := h.ok(changed, "apply", "-f", "-"); !strings.Contains(out, "silo/hello unchanged") {
		t.Fatalf("third apply (no change):\n%s", out)
	}
	y := h.ok("", "get", "silo", "hello", "-n", "demo", "-o", "yaml")
	for _, want := range []string{"cpu: 4", "generation: 2", "kind: Silo", "resourceVersion:"} {
		if !strings.Contains(y, want) {
			t.Fatalf("get -o yaml missing %q:\n%s", want, y)
		}
	}

	time.Sleep(200 * time.Millisecond) // let the watch print, then stop it
	cancel()
	wg.Wait()
	if !strings.Contains(wout, "MODIFIED silo/demo/hello") {
		t.Fatalf("watch didn't report the update:\n%s", wout)
	}

	// The API refuses invalid objects, and kvo says why.
	bad := strings.Replace(manifest, "runtime: cloud-hypervisor", "runtime: kubernetes", 1)
	_, errs, code := h.kvo(context.Background(), bad, "apply", "-f", "-")
	if code == 0 || !strings.Contains(errs, "spec.runtime must be one of") {
		t.Fatalf("invalid apply: exit %d, stderr %q", code, errs)
	}

	// delete, then get fails with NotFound.
	if out := h.ok("", "delete", "silo", "hello", "-n", "demo"); !strings.Contains(out, "silo/hello deleted") {
		t.Fatalf("delete:\n%s", out)
	}
	if _, errs, code := h.kvo(context.Background(), "", "get", "silo", "hello", "-n", "demo"); code == 0 || !strings.Contains(errs, "NotFound") {
		t.Fatalf("get after delete: exit %d, %q", code, errs)
	}
}

func TestKvoUsageErrors(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"get"}, {"get", "pods"}, {"frobnicate"}, {"apply"}, {"get", "silos", "--bogus"}} {
		if _, _, code := h.kvo(context.Background(), "", args...); code == 0 {
			t.Errorf("kvo %v: want a non-zero exit", args)
		}
	}
}
