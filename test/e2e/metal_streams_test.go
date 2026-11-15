//go:build metal

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The streams (exec, a terminal, kvo cp) through the real kvo binary, as a person runs it, on the
// cluster: every one goes through the client's upgrade path, kvo → API server → the host's
// agent tunnel. Two regressions broke exactly that while every unit test of exec passed: a
// response wrapper that hid a 101's stream (K-008), and an agent tunnel refused as unstamped.
func kvoStreams(t *testing.T, ctx context.Context, bin, ns, silo string) {
	t.Helper()
	run := func(stdin []byte, args ...string) (string, string, int) {
		cmd := exec.CommandContext(ctx, bin, args...)
		var o, e bytes.Buffer
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &o, &e
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			code = -1
		}
		return strings.TrimSpace(o.String()), strings.TrimSpace(e.String()), code
	}
	// exec: stdout, stderr and the exit code, apart.
	out, errOut, code := run(nil, "exec", "silo", silo, "-n", ns, "--", "sh", "-c", "echo out; echo err >&2; exit 3")
	if out != "out" || !strings.Contains(errOut, "err") || code != 3 {
		t.Errorf("%s: kvo exec: stdout %q stderr %q exit %d, want out, err, 3", silo, out, errOut, code)
	} else {
		t.Logf("%s: kvo exec: stdout, stderr and exit 3 apart", silo)
	}
	// kvo cp, in and out, a MiB checked both ways.
	dir := t.TempDir()
	data := make([]byte, 1<<20)
	_, _ = rand.Read(data)
	sum := sha256.Sum256(data)
	in := filepath.Join(dir, "blob")
	if err := os.WriteFile(in, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if o, e, code := run(nil, "cp", in, "silo/"+silo+":/tmp/kvt-blob", "-n", ns); code != 0 {
		t.Fatalf("%s: kvo cp in: exit %d %s %s", silo, code, o, e)
	}
	got, _, _ := run(nil, "exec", "silo", silo, "-n", ns, "--", "sh", "-c", "sha256sum /tmp/kvt-blob | cut -d' ' -f1")
	if got != hex.EncodeToString(sum[:]) {
		t.Errorf("%s: kvo cp in: the silo has %q", silo, got)
	}
	back := filepath.Join(dir, "back")
	if o, e, code := run(nil, "cp", "silo/"+silo+":/tmp/kvt-blob", back, "-n", ns); code != 0 {
		t.Fatalf("%s: kvo cp out: exit %d %s %s", silo, code, o, e)
	}
	if b, _ := os.ReadFile(back); !bytes.Equal(b, data) {
		t.Errorf("%s: kvo cp out: %d bytes back, not the same", silo, len(b))
	} else {
		t.Logf("%s: kvo cp in and out: the same MiB", silo)
	}
	// A terminal: a pty in the silo, its exit code.
	p := startPty(t, ctx, bin, 27, 91, "exec", "-it", "silo", silo, "-n", ns, "--", "sh", "-c", `echo "tty=$(tty) size=$(stty size)"; exit 4`)
	p.waitFor(silo+": kvo exec -it: a terminal of this size", regexp.MustCompile(`tty=/dev/pts/\d+ size=27 91`), 2*time.Minute)
	if code := p.exit(time.Minute); code != 4 {
		t.Errorf("%s: kvo exec -it: exit %d, want 4", silo, code)
	}
}

// TestMetalKvoStreams is kvoStreams on the one machine, into a microVM and a docker silo.
//
// Listens on nothing outside.
func TestMetalKvoStreams(t *testing.T) {
	c := metal(t)
	ns := "streams"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + "---\n" + boxEcho(ns, "box", 8080))
	c.waitRunning(ns, 20*time.Minute, "vm", "box")
	bin := buildKvo(t)
	for _, s := range []string{"vm", "box"} {
		kvoStreams(t, c.ctx, bin, ns, s)
	}
}

// TestMetal2KvoStreams is kvoStreams on two machines, into silos on each (machine 2's streams
// come through its agent's tunnel to the system node on machine 1).
//
// Listens on nothing outside.
func TestMetal2KvoStreams(t *testing.T) {
	p := metal2(t)
	p.ensureTwoWorkers()
	c := p.c1
	ns := "streams2"
	c.namespace(ns)
	c.apply(vmEcho(ns, "vm", 8080) + on(metalHost2) + "---\n" + boxEcho(ns, "box1", 8080) + on(metalHost) + "---\n" + boxEcho(ns, "box2", 8080) + on(metalHost2))
	c.waitRunning(ns, 20*time.Minute, "vm", "box1", "box2")
	bin := buildKvo(t)
	for _, s := range []string{"vm", "box1", "box2"} {
		kvoStreams(t, c.ctx, bin, ns, s)
	}
}
