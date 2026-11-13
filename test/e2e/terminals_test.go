//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

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

// TestTerminalsAndUI is M15 on real machines, on every runtime that has a pty of its own here:
// cloud-hypervisor (ssh pty-req inside the guest), openshell (a VM sandbox) and
// openshell-container (a Docker sandbox), each through the agent's channel. For each: kvo exec -it
// on a pty of the Mac's (its size, a resize followed, the exit code), kvo ssh (a login shell on a
// terminal), and a client killed with -9 stops the command in the silo, with and without a pty.
// Then kvo ui against the microVM: the page with its one-time token, the terminal's WebSocket,
// listing a folder, a download and an upload; a second use of the token, another Origin and
// another Host are refused.
//
//	metal  control plane + worker with KVM: cloud-hypervisor, openshell, openshell-container
func TestTerminalsAndUI(t *testing.T) {
	r := newRig(t, 60*time.Minute, map[string]testbed.Spec{
		"metal": {Role: "metal", CPUs: 6, Memory: "10GiB", Disk: "40GiB", KVM: true, Shared: true},
	})
	kvoBin := buildKvo(t)
	metalIP := r.ip("metal")
	r.must(kvoadm.Run, "", append(append([]string{"init"}, r.sshArgs("metal")...),
		"--name", "metal-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443", "--address", metalIP, "--worker",
		"--runtime", "cloud-hypervisor", "--runtime", "openshell", "--runtime", "openshell-container",
		"--openshell-gateway-scope", "namespace", "--loop-storage", "20G")...)
	r.must(kvo.Run, `apiVersion: kevaso/v1
kind: Namespace
metadata: { name: tt }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: ch, namespace: tt }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 768Mi }
  disk: { size: 5Gi }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: osvm, namespace: tt }
spec:
  runtime: openshell
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 1Gi }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: osct, namespace: tt }
spec:
  runtime: openshell-container
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 1Gi }
`, "apply", "-f", "-")
	r.waitRunning("tt", 35*time.Minute, "metal", "ch", "osvm", "osct")

	for _, silo := range []string{"ch", "osvm", "osct"} {
		t.Run(silo, func(t *testing.T) {
			r := r.on(t)
			// kvo exec -it: the Mac's terminal size, a resize, the exit code.
			p := startPty(t, r.ctx, kvoBin, 31, 101, "exec", "-it", "silo", silo, "-n", "tt", "--",
				"sh", "-c", `echo "tty=$(tty) size=$(stty size)"; read x; echo "size=$(stty size)"; exit 7`)
			m := p.waitFor("kvo exec -it: a terminal of the Mac's size", regexp.MustCompile(`tty=(\S+) size=31 101`), 90*time.Second)
			if !strings.HasPrefix(m[1], "/dev/pts/") {
				t.Errorf("not a pty: %q", m[1])
			}
			time.Sleep(time.Second)
			if err := pty.Setsize(p.tty, &pty.Winsize{Rows: 47, Cols: 133}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * time.Second) // SIGWINCH → kvo → the agent → the silo's pty
			p.send("\r")
			p.waitFor("kvo exec -it: the resize reached the silo", regexp.MustCompile(`size=47 133`), 30*time.Second)
			if code := p.exit(30 * time.Second); code != 7 {
				t.Errorf("kvo exec -it exit code: %d, want 7", code)
			} else {
				t.Log("kvo exec -it exited with the command's code, 7")
			}
			if strings.Count(p.out.String(), "size=") != 2 {
				t.Errorf("terminal: %q", p.out.String())
			}

			// kvo ssh: a login shell on a terminal; Ctrl-C reaches the shell's foreground job, not kvo.
			p = startPty(t, r.ctx, kvoBin, 25, 90, "ssh", "silo", silo, "-n", "tt")
			p.send("echo \"login=$0 tty=$(tty) size=$(stty size)\"\r")
			p.waitFor("kvo ssh: a login shell on a pty", regexp.MustCompile(`login=-?\S+ tty=/dev/pts/\d+ size=25 90`), 90*time.Second)
			// (Not "sleep; echo $?" on one line: bash drops the rest of a list whose job died of SIGINT.)
			p.send("sleep 300\r")
			time.Sleep(2 * time.Second)
			p.send("\x03")
			time.Sleep(time.Second)
			p.send("echo after-ctrl-c=$?\r")
			p.waitFor("kvo ssh: Ctrl-C stops the shell's job, not the shell", regexp.MustCompile(`after-ctrl-c=130`), 30*time.Second)
			p.send("exit 3\r")
			if code := p.exit(30 * time.Second); code != 3 {
				t.Errorf("kvo ssh exit code: %d, want 3", code)
			}

			// A dropped client (kvo killed with -9) stops the command in the silo: on a terminal and not.
			for i, tty := range []bool{true, false} {
				marker := fmt.Sprintf("%d", 4241+i)
				args := []string{"exec", "silo", silo, "-n", "tt", "--", "sh", "-c", "echo started; exec sleep " + marker}
				var c *exec.Cmd
				if tty {
					p = startPty(t, r.ctx, kvoBin, 24, 80, append([]string{"exec", "-it"}, args[1:]...)...)
					p.waitFor("kvo exec -it sleep started", regexp.MustCompile(`started`), 60*time.Second)
					c = p.cmd
				} else {
					var out safeBuffer
					c = exec.CommandContext(r.ctx, kvoBin, args...)
					c.Stdout, c.Stderr = &out, &out
					if err := c.Start(); err != nil {
						t.Fatal(err)
					}
					r.eventually("kvo exec sleep started", 60*time.Second, func() (bool, string) {
						return strings.Contains(out.String(), "started"), out.String()
					})
				}
				running := func() string {
					o, _ := r.in("tt", silo, "ps -eo args | grep -c '^sleep "+marker+"' || true")
					return strings.TrimSpace(o)
				}
				if got := running(); got != "1" {
					t.Errorf("tty=%v: sleep %s isn't running in the silo: %q", tty, marker, got)
				}
				_ = c.Process.Kill()
				killed := time.Now()
				if r.eventually(fmt.Sprintf("tty=%v: kvo killed -9 → the command is stopped in the silo", tty), 45*time.Second, func() (bool, string) {
					got := running()
					return got == "0", got
				}) {
					t.Logf("tty=%v: gone %s after the client was killed", tty, time.Since(killed).Round(time.Second))
				}
			}
		})
	}

	t.Run("ui", func(t *testing.T) { siloUI(r.on(t), kvoBin) })
}

// siloUI drives kvo ui silo ch like a browser would.
func siloUI(r *rig, kvoBin string) {
	t := r.t
	var out safeBuffer
	c := exec.CommandContext(r.ctx, kvoBin, "ui", "silo", "ch", "-n", "tt", "--no-browser")
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	var link string
	r.eventually("kvo ui prints its link", 30*time.Second, func() (bool, string) {
		link = regexp.MustCompile(`http://127\.0\.0\.1:\d+/\?token=\S+`).FindString(out.String())
		return link != "", out.String()
	})
	if link == "" {
		t.FailNow()
	}
	u, _ := url.Parse(link)
	origin := "http://" + u.Host
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 2 * time.Minute}
	do := func(cl *http.Client, method, path string, body io.Reader, hdr map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(r.ctx, method, origin+path, body)
		for k, v := range hdr {
			if k == "Host" {
				req.Host = v
				continue
			}
			req.Header.Set(k, v)
		}
		if b, ok := body.(*bytes.Reader); ok {
			req.ContentLength = int64(b.Len())
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	// The link: once, then it's a cookie.
	code, page := do(browser, "GET", "/?"+u.RawQuery, nil, nil)
	if code != 200 || !strings.Contains(page, "<html") {
		t.Fatalf("the page with its token: %d %.200q", code, page)
	}
	t.Log("the link opened the page (token swapped for a cookie)")
	other, _ := cookiejar.New(nil)
	stranger := &http.Client{Jar: other, Timeout: time.Minute}
	if code, body := do(stranger, "GET", "/?"+u.RawQuery, nil, nil); code != http.StatusForbidden {
		t.Errorf("a second use of the token: %d %q", code, body)
	} else {
		t.Log("a second use of the token: refused (403)")
	}
	if code, _ := do(stranger, "GET", "/api/info", nil, nil); code != http.StatusUnauthorized {
		t.Errorf("without the cookie: %d", code)
	}
	if code, body := do(browser, "GET", "/api/info", nil, map[string]string{"Origin": "http://evil.example"}); code != http.StatusForbidden {
		t.Errorf("another Origin: %d %q", code, body)
	}
	if code, body := do(browser, "GET", "/api/info", nil, map[string]string{"Host": "kvo.attacker.test:" + u.Port()}); code != http.StatusMisdirectedRequest {
		t.Errorf("another Host (DNS rebinding): %d %q", code, body)
	}
	if code, body := do(browser, "GET", "/api/info", nil, nil); code != 200 || !strings.Contains(body, `"ch"`) {
		t.Errorf("info: %d %q", code, body)
	}

	// Files: list, upload (needs the page's Origin), download.
	data := []byte("uploaded through kvo ui ✓\n\x00\x01 binary")
	if code, body := do(browser, "POST", "/api/upload?dir=/tmp&name=up.bin", bytes.NewReader(data), nil); code != http.StatusForbidden {
		t.Errorf("an upload without the page's Origin: %d %q", code, body)
	}
	if code, body := do(browser, "POST", "/api/upload?dir=/tmp&name=up.bin", bytes.NewReader(data), map[string]string{"Origin": "http://evil.example"}); code != http.StatusForbidden {
		t.Errorf("an upload from another Origin: %d %q", code, body)
	}
	if code, body := do(browser, "POST", "/api/upload?dir=/tmp&name=up.bin", bytes.NewReader(data), map[string]string{"Origin": origin}); code != 200 {
		t.Fatalf("upload: %d %q", code, body)
	}
	if got, code := r.in("tt", "ch", "sha256sum /tmp/up.bin | cut -c1-16; stat -c %s /tmp/up.bin"); code != 0 || !strings.Contains(got, fmt.Sprint(len(data))) {
		t.Errorf("the uploaded file in the silo: %q", got)
	}
	code, list := do(browser, "GET", "/api/list?path=/tmp", nil, nil)
	if code != 200 || !strings.Contains(list, `"up.bin"`) {
		t.Errorf("list /tmp: %d %q", code, list)
	} else {
		t.Log("list /tmp shows the upload")
	}
	if code, got := do(browser, "GET", "/api/download?path=/tmp/up.bin", nil, nil); code != 200 || got != string(data) {
		t.Errorf("download: %d %q", code, got)
	} else {
		t.Log("download: byte for byte")
	}
	if code, _ := do(browser, "GET", "/api/download?path=/etc", nil, nil); code != 200 {
		t.Errorf("a folder's download (tar): %d", code)
	}

	// The terminal's WebSocket: a shell, a command, its exit code.
	wsURL := "ws://" + u.Host + "/ws/terminal?rows=30&cols=100"
	hdr := http.Header{}
	for _, ck := range jar.Cookies(&url.URL{Scheme: "http", Host: u.Host, Path: "/"}) {
		hdr.Add("Cookie", ck.Name+"="+ck.Value)
	}
	bad := hdr.Clone()
	bad.Set("Origin", "http://evil.example")
	if _, resp, err := websocket.Dial(r.ctx, wsURL, &websocket.DialOptions{HTTPHeader: bad}); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("a WebSocket from another Origin: %v %v", err, resp)
	} else {
		t.Log("a WebSocket from another Origin: refused (403)")
	}
	good := hdr.Clone()
	good.Set("Origin", origin)
	ws, _, err := websocket.Dial(r.ctx, wsURL, &websocket.DialOptions{HTTPHeader: good})
	if err != nil {
		t.Fatalf("the terminal's WebSocket: %v", err)
	}
	defer func() { _ = ws.CloseNow() }()
	var term safeBuffer
	exit := make(chan string, 1)
	var once sync.Once
	go func() {
		for {
			typ, b, err := ws.Read(r.ctx)
			if err != nil {
				once.Do(func() { exit <- "read: " + err.Error() })
				return
			}
			if typ == websocket.MessageBinary {
				_, _ = term.Write(b)
				continue
			}
			once.Do(func() { exit <- string(b) })
		}
	}()
	_ = ws.Write(r.ctx, websocket.MessageBinary, []byte("echo \"size=$(stty size)\"; ls /tmp | grep up.bin; exit 5\r"))
	select {
	case msg := <-exit:
		var m struct {
			Exit *int `json:"exit"`
		}
		_ = json.Unmarshal([]byte(msg), &m)
		if m.Exit == nil || *m.Exit != 5 {
			t.Errorf("the terminal's end: %q; it showed %q", msg, term.String())
		}
	case <-time.After(90 * time.Second):
		t.Errorf("the terminal never ended; it showed %q", term.String())
	}
	// What a person would see: without the escapes (bracketed paste, the prompt's title, grep's colours).
	plain := regexp.MustCompile(`\x1b(\[[0-9;?]*[A-Za-z]|\][^\a]*\a)`).ReplaceAllString(term.String(), "")
	sc := bufio.NewScanner(strings.NewReader(plain))
	sawSize, sawFile := false, false
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		sawSize = sawSize || strings.HasPrefix(l, "size=30 100")
		sawFile = sawFile || l == "up.bin"
	}
	if !sawSize || !sawFile {
		t.Errorf("the web terminal: size %v, ls %v: %q", sawSize, sawFile, term.String())
	} else {
		t.Log("the web terminal ran a command at its size, listed the upload, exited 5")
	}
}
