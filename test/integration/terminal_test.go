package integration

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// siloFS is the fake silo's file system, behind the tar and ls the API server runs in it.
type siloFS struct {
	mu    sync.Mutex
	files map[string][]byte
	dirs  map[string]bool
	noTar bool // an image without tar
}

func (f *siloFS) program(sleeping chan<- struct{}) func(context.Context, kri.ID, kri.ExecRequest) int {
	return func(ctx context.Context, _ kri.ID, req kri.ExecRequest) int {
		cmd := req.Command
		out := func(format string, a ...any) { _, _ = fmt.Fprintf(req.Stdout, format, a...) }
		errOut := func(s string) {
			if req.Stderr != nil {
				_, _ = io.WriteString(req.Stderr, s)
			}
		}
		switch {
		case slices.Equal(cmd, apiserver.LoginShell):
			out("login shell, terminal %v %dx%d\n", req.TTY != nil, req.TTY.Size.Rows, req.TTY.Size.Cols)
			return 0
		case cmd[0] == "tty-echo":
			if req.TTY == nil {
				out("no terminal\n")
				return 1
			}
			out("size %dx%d\n", req.TTY.Size.Rows, req.TTY.Size.Cols)
			lines := make(chan string)
			go func() {
				sc := bufio.NewScanner(req.Stdin)
				for sc.Scan() {
					lines <- sc.Text()
				}
				close(lines)
			}()
			for {
				select {
				case sz := <-req.TTY.Resize:
					out("resized %dx%d\n", sz.Rows, sz.Cols)
				case l, ok := <-lines:
					if !ok || l == "exit" {
						return 7
					}
					out("echo %s\n", l)
				}
			}
		case cmd[0] == "sleep":
			sleeping <- struct{}{}
			<-ctx.Done() // until killed
			return -1
		case cmd[0] == "tar" && f.noTar:
			errOut(`exec: "tar": executable file not found in $PATH`)
			return 127
		case cmd[0] == "tar" && cmd[1] == "-xf":
			return f.untar(cmd[4], req.Stdin, errOut)
		case cmd[0] == "tar" && cmd[1] == "-cf":
			return f.tar(cmd[4], cmd[5], req.Stdout, errOut)
		case cmd[0] == "ls" && cmd[1] == "-lAn":
			f.mu.Lock()
			defer f.mu.Unlock()
			dir := path.Clean(cmd[3])
			out("total 0\n")
			for p := range f.dirs {
				if p != dir && path.Dir(p) == dir {
					out("drwxr-xr-x 2 0 0 4096 Nov 13 01:50 %s\n", path.Base(p))
				}
			}
			for p, b := range f.files {
				if path.Dir(p) == dir {
					out("-rw-r--r-- 1 0 0 %d Nov 13 01:50 %s\n", len(b), path.Base(p))
				}
			}
			return 0
		case cmd[0] == "ls" && cmd[1] == "-ldn":
			f.mu.Lock()
			defer f.mu.Unlock()
			p := cmd[3]
			switch {
			case f.dirs[p]:
				out("drwxr-xr-x 2 0 0 4096 Nov 13 01:50 %s\n", p)
			case f.files[p] != nil:
				out("-rw-r--r-- 1 0 0 %d Nov 13 01:50 %s\n", len(f.files[p]), p)
			default:
				errOut("ls: " + p + ": No such file or directory")
				return 2
			}
			return 0
		}
		errOut("unknown command " + strings.Join(cmd, " "))
		return 126
	}
}

func (f *siloFS) untar(dir string, in io.Reader, errOut func(string)) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dirs[dir] {
		_, _ = io.Copy(io.Discard, in)
		errOut("tar: " + dir + ": Cannot open: No such file or directory")
		return 2
	}
	tr := tar.NewReader(in)
	for {
		h, err := tr.Next()
		if err != nil {
			return 0
		}
		p := path.Join(dir, h.Name)
		if h.Typeflag == tar.TypeDir {
			f.dirs[p] = true
			continue
		}
		b, _ := io.ReadAll(tr)
		f.files[p] = b
	}
}

func (f *siloFS) tar(dir, base string, out io.Writer, errOut func(string)) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	top := path.Join(dir, base)
	if !f.dirs[top] && f.files[top] == nil {
		errOut("tar: " + base + ": Cannot stat: No such file or directory")
		return 2
	}
	tw := tar.NewWriter(out)
	var names []string
	for p := range f.dirs {
		if p == top || strings.HasPrefix(p, top+"/") {
			names = append(names, p)
		}
	}
	for p := range f.files {
		if p == top || strings.HasPrefix(p, top+"/") {
			names = append(names, p)
		}
	}
	slices.Sort(names)
	for _, p := range names {
		name := "./" + path.Join(strings.TrimPrefix(base, "./"), strings.TrimPrefix(p, top))
		if f.dirs[p] {
			_ = tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o755})
			continue
		}
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.files[p]))})
		_, _ = tw.Write(f.files[p])
	}
	_ = tw.Close()
	return 0
}

// runningSilo is TestKvoExec's set-up: silo demo/hello on hv1, whose agent runs the fake runtime.
func runningSilo(t *testing.T, rt *fake.Runtime) (*harness, context.Context, *client.Client) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	a := &agent.Agent{Client: client.New(h.server), HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	h.ok(manifest, "apply", "-f", "-")
	c := client.New(h.server)
	var s v1.Silo
	if err := c.Get(ctx, "Silo", "demo", "hello", &s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}
	for { // until the agent is connected and the silo running
		_, errs, code := h.kvo(ctx, "", "ssh", "silo", "hello", "-n", "demo")
		if code == 0 {
			return h, ctx, c
		}
		starting := strings.Contains(errs, "HostNotConnected") || strings.Contains(errs, "not found") || strings.Contains(errs, "not running")
		if ctx.Err() != nil || !starting {
			t.Fatalf("kvo ssh: exit %d: %s", code, errs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// syncBuf is an io.Writer tests read while it's written.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitOutput(t *testing.T, b *syncBuf, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(b.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in %q", want, b.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A terminal end to end: kvo → API server → tunnel → agent → runtime, with its size, a resize, the
// exit code, and kvo ssh's login shell.
func TestTerminalThroughTheTunnel(t *testing.T) {
	rt := fake.New()
	fs := &siloFS{files: map[string][]byte{}, dirs: map[string]bool{"/": true}}
	rt.Program = fs.program(make(chan struct{}, 1))
	h, ctx, c := runningSilo(t, rt)

	out, errs, code := h.kvo(ctx, "", "ssh", "silo", "hello", "-n", "demo")
	if code != 0 || out != "login shell, terminal true 24x80\n" {
		t.Fatalf("kvo ssh: exit %d %q %q", code, out, errs)
	}
	if _, _, code := h.kvo(ctx, "", "ssh", "silo", "hello", "-n", "demo", "--", "ls"); code == 0 {
		t.Fatal("kvo ssh with a command: want a usage error")
	}
	out, errs, code = h.kvo(ctx, "one\nexit\n", "exec", "-it", "silo", "hello", "-n", "demo", "--", "tty-echo")
	if code != 7 || out != "size 24x80\necho one\n" {
		t.Fatalf("kvo exec -it: exit %d %q %q", code, out, errs)
	}
	if out, _, code := h.kvo(ctx, "", "exec", "silo", "hello", "-n", "demo", "--", "tty-echo"); code != 1 || out != "no terminal\n" {
		t.Fatalf("kvo exec without -t: exit %d %q", code, out)
	}

	s, err := c.OpenExec(ctx, "demo", "hello", client.ExecRequest{Command: []string{"tty-echo"}, TTY: true, Rows: 30, Cols: 90})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var term syncBuf
	done := make(chan int, 1)
	go func() { code, _ := s.Wait(&term, &term); done <- code }()
	waitOutput(t, &term, "size 30x90\n")
	if err := s.Resize(50, 132); err != nil {
		t.Fatal(err)
	}
	waitOutput(t, &term, "resized 50x132\n")
	_, _ = s.Write([]byte("hello\nexit\n"))
	select {
	case code := <-done:
		if code != 7 || !strings.Contains(term.String(), "echo hello\n") {
			t.Fatalf("exit %d, %q", code, term.String())
		}
	case <-ctx.Done():
		t.Fatal("no exit code")
	}
}

// The client goes away mid-command: the command is stopped on the host, not left running.
func TestCommandStopsWhenItsClientGoesAway(t *testing.T) {
	rt := fake.New()
	sleeping := make(chan struct{}, 1)
	rt.Program = (&siloFS{}).program(sleeping)
	_, ctx, c := runningSilo(t, rt)
	for _, tty := range []bool{false, true} {
		cctx, cancel := context.WithCancel(ctx)
		s, err := c.OpenExec(cctx, "demo", "hello", client.ExecRequest{Command: []string{"sleep", "1000"}, TTY: tty})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = s.Wait(io.Discard, io.Discard) }()
		<-sleeping
		if rt.Running() != 1 {
			t.Fatalf("running %d", rt.Running())
		}
		killed := rt.Killed()
		cancel() // kvo exits, or its connection drops: the stream ends
		deadline := time.Now().Add(10 * time.Second)
		for rt.Running() != 0 || rt.Killed() != killed+1 {
			if time.Now().After(deadline) {
				t.Fatalf("tty %v: still running %d, killed %d", tty, rt.Running(), rt.Killed())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// kvo cp in and out, through tar in the silo; the size limit; an image without tar.
func TestCopyBothWays(t *testing.T) {
	rt := fake.New()
	fs := &siloFS{files: map[string][]byte{}, dirs: map[string]bool{"/": true, "/srv": true}}
	rt.Program = fs.program(make(chan struct{}, 1))
	h, ctx, _ := runningSilo(t, rt)

	src := filepath.Join(t.TempDir(), "app")
	_ = os.MkdirAll(filepath.Join(src, "conf"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "main.go"), []byte("package main"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "conf", "app.yaml"), []byte("port: 8080"), 0o644)

	// Into a folder that exists: the copy goes inside it.
	out, errs, code := h.kvo(ctx, "", "cp", src, "silo/hello:/srv", "-n", "demo")
	if code != 0 || !strings.Contains(out, "silo/hello:/srv/app: 2 files") {
		t.Fatalf("cp in: exit %d %q %q", code, out, errs)
	}
	fs.mu.Lock()
	got := string(fs.files["/srv/app/conf/app.yaml"])
	fs.mu.Unlock()
	if got != "port: 8080" {
		t.Fatalf("in the silo: %q", got)
	}
	// One file, to a new name.
	if _, errs, code := h.kvo(ctx, "", "cp", filepath.Join(src, "main.go"), "silo/hello:/srv/renamed.go", "-n", "demo"); code != 0 {
		t.Fatalf("cp a file: %s", errs)
	}
	fs.mu.Lock()
	got = string(fs.files["/srv/renamed.go"])
	fs.mu.Unlock()
	if got != "package main" {
		t.Fatalf("renamed: %q", got)
	}

	// Back out, as a new folder, and into a folder that exists.
	dst := t.TempDir()
	if _, errs, code := h.kvo(ctx, "", "cp", "silo/hello:/srv/app", filepath.Join(dst, "back"), "-n", "demo"); code != 0 {
		t.Fatalf("cp out: %s", errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "back", "conf", "app.yaml")); string(b) != "port: 8080" {
		t.Fatalf("copied back: %q", b)
	}
	if _, errs, code := h.kvo(ctx, "", "cp", "silo/hello:/srv/renamed.go", dst, "-n", "demo"); code != 0 {
		t.Fatalf("cp a file out: %s", errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "renamed.go")); string(b) != "package main" {
		t.Fatalf("file copied back: %q", b)
	}

	// Over the limit, both ways.
	if _, errs, code := h.kvo(ctx, "", "cp", src, "silo/hello:/srv/", "-n", "demo", "--max-size", "5"); code == 0 || !strings.Contains(errs, "over the size limit") {
		t.Fatalf("cp in over the limit: exit %d %q", code, errs)
	}
	if _, errs, code := h.kvo(ctx, "", "cp", "silo/hello:/srv/app", filepath.Join(dst, "small"), "-n", "demo", "--max-size", "5"); code == 0 || !strings.Contains(errs, "over the size limit") {
		t.Fatalf("cp out over the limit: exit %d %q", code, errs)
	}
	// Mistakes.
	for _, bad := range [][]string{{"cp", "a", "b"}, {"cp", "silo/hello:/a", "silo/hello:/b"}, {"cp", src, "silo/hello:relative"}, {"cp", src}} {
		if _, _, code := h.kvo(ctx, "", append(bad, "-n", "demo")...); code == 0 {
			t.Errorf("kvo %v: want an error", bad)
		}
	}
	if _, errs, code := h.kvo(ctx, "", "cp", "silo/hello:/nope", dst, "-n", "demo"); code == 0 || !strings.Contains(errs, "No such file") {
		t.Fatalf("cp of nothing: %d %q", code, errs)
	}

	// An image without tar: a clear refusal.
	fs.mu.Lock()
	fs.noTar = true
	fs.mu.Unlock()
	if _, errs, code := h.kvo(ctx, "", "cp", src, "silo/hello:/srv/", "-n", "demo"); code == 0 || !strings.Contains(errs, "silo/hello has no tar in its image") {
		t.Fatalf("no tar: exit %d %q", code, errs)
	}
}
