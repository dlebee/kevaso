//go:build e2e || metal

package e2e

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

// Helpers shared by the Lima tests (e2e) and the bare-metal ones (metal).

// hgetGo is a tiny HTTP client for the silos (OpenShell's default image has no curl or python):
// hget URL [HEADER=VALUE]… prints the status and body, or "error: …".
const hgetGo = `package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	req, _ := http.NewRequest("GET", os.Args[1], nil)
	for _, h := range os.Args[2:] {
		k, v, _ := strings.Cut(h, "=")
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.StatusCode, string(b))
}
`

// ptyKvo is kvo running on a real terminal (a pty on the Mac), as a person runs it.
type ptyKvo struct {
	t    *testing.T
	cmd  *exec.Cmd
	tty  *os.File
	out  safeBuffer
	done chan struct{}
	code int
}

// buildKvo builds kvo for the Mac, once per test.
func buildKvo(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "kvo")
	c := exec.Command("go", "build", "-o", bin, "kevaso.com/core/cmd/kvo")
	c.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("build kvo: %v\n%s", err, out)
	}
	return bin
}

func startPty(t *testing.T, ctx context.Context, bin string, rows, cols uint16, args ...string) *ptyKvo {
	t.Helper()
	p := &ptyKvo{t: t, cmd: exec.CommandContext(ctx, bin, args...), done: make(chan struct{})}
	tty, err := pty.StartWithSize(p.cmd, &pty.Winsize{Rows: rows, Cols: cols})
	if err != nil {
		t.Fatal(err)
	}
	p.tty = tty
	go func() { _, _ = io.Copy(&p.out, tty) }()
	go func() {
		err := p.cmd.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			p.code = ee.ExitCode()
		} else if err != nil {
			p.code = -1
		}
		close(p.done)
	}()
	t.Cleanup(func() { _ = p.cmd.Process.Kill(); _ = tty.Close() })
	return p
}

// waitFor waits until the terminal has printed something matching re.
func (p *ptyKvo) waitFor(what string, re *regexp.Regexp, within time.Duration) []string {
	p.t.Helper()
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		if m := re.FindStringSubmatch(p.out.String()); m != nil {
			p.t.Logf("%s: ok", what)
			return m
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatalf("%s: never printed %s; the terminal shows:\n%q", what, re, p.out.String())
	return nil
}

func (p *ptyKvo) send(s string) {
	if _, err := p.tty.Write([]byte(s)); err != nil {
		p.t.Fatal(err)
	}
}

// exit waits for kvo to end and returns its exit code.
func (p *ptyKvo) exit(within time.Duration) int {
	p.t.Helper()
	select {
	case <-p.done:
		return p.code
	case <-time.After(within):
		p.t.Fatalf("kvo didn't end within %s; the terminal shows:\n%q", within, p.out.String())
	}
	return 0
}

// safeBuffer is a bytes.Buffer safe for one writer and readers at once.
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
