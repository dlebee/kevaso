package apiserver

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/pki"
)

func TestFileCommand(t *testing.T) {
	for _, c := range []struct {
		op, path string
		want     []string
	}{
		{client.FileRead, "/srv/app/", []string{"tar", "-cf", "-", "-C", "/srv/", "./app"}},
		{client.FileRead, "/tmp/-rf", []string{"tar", "-cf", "-", "-C", "/tmp/", "./-rf"}}, // never an option
		{client.FileRead, "/", []string{"tar", "-cf", "-", "-C", "/", "."}},
		{client.FileWrite, "/srv/../srv/x", []string{"tar", "-xf", "-", "-C", "/srv/x"}},
		{client.FileList, "/etc", []string{"ls", "-lAn", "--", "/etc/"}},
		{client.FileList, "/", []string{"ls", "-lAn", "--", "/"}},
		{client.FileStat, "/etc/hosts", []string{"ls", "-ldn", "--", "/etc/hosts"}},
	} {
		got, err := FileCommand(c.op, c.path)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s %s: %q %v, want %q", c.op, c.path, got, err, c.want)
		}
	}
	for _, bad := range [][2]string{{client.FileRead, "relative"}, {client.FileRead, ""}, {client.FileList, "/a\nb"}, {"rm", "/"}} {
		if _, err := FileCommand(bad[0], bad[1]); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

// RBAC terms of the new subresources, and worker hosts never get them.
func TestSiloStreamAttributes(t *testing.T) {
	id := pki.Identity{Type: "user", Name: "bob"}
	for _, c := range []struct {
		method, path, verb, res string
	}{
		{http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/ssh", "create", "silos/ssh"},
		{http.MethodGet, "/apis/kevaso/v1/namespaces/dev/silos/web/files?op=read&path=/x", "get", "silos/files"},
		{http.MethodPost, "/apis/kevaso/v1/namespaces/dev/silos/web/files?op=write&path=/x", "create", "silos/files"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		tg, err := parsePath(r.URL.Path)
		if err != nil {
			t.Fatal(err)
		}
		a := attributes(id, nil, r, tg)
		if a.Verb != c.verb || a.Resource != c.res || a.Name != "web" || a.Namespace != "dev" {
			t.Errorf("%s %s: %+v", c.method, c.path, a)
		}
		if hostAuthorize(pki.Identity{Type: "host", Name: "hv1", Role: "worker"}, r, tg) {
			t.Errorf("a worker host may %s %s", c.method, c.path)
		}
	}
	if _, err := parsePath("/apis/kevaso/v1/namespaces/dev/hosts/web/ssh"); err == nil {
		t.Error("ssh on a host")
	}
}

// The capped relay ends a transfer once either way is over its limit, telling the client why.
func TestRelayLimited(t *testing.T) {
	for _, way := range []string{"upload", "download"} {
		cli, srvSide := net.Pipe()
		agentSide, agent := net.Pipe()
		go (&Server{}).relay(srvSide, bufio.NewReader(srvSide), agentSide, 10, "test")
		go func() { // the agent: reads frames, answers with output
			br := bufio.NewReader(agent)
			if way == "download" {
				_ = client.WriteFrame(agent, client.FrameStdout, []byte("0123456789"))
				_ = client.WriteFrame(agent, client.FrameStdout, []byte("x"))
			}
			for {
				if _, _, err := client.ReadFrame(br); err != nil {
					return
				}
			}
		}()
		if way == "upload" {
			go func() {
				_ = client.WriteFrame(cli, client.FrameStdin, []byte("01234"))
				_ = client.WriteFrame(cli, client.FrameStdin, []byte("567890"))
			}()
		}
		_, err := client.ReadOutput(cli, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "the "+way+" is over the 10 byte limit") {
			t.Errorf("%s: %v", way, err)
		}
		_ = cli.Close()
		_ = agent.Close()
	}
}

// A command that ends before the client has sent everything (here its stdin close, late): the
// client still gets every frame and the exit code, then EOF, and nothing is logged. The server
// half-closes and drains instead of closing at once: closing a socket that bytes then arrive at
// makes the kernel answer with a reset, which can drop what the client hadn't received yet (the
// suspected cause of "exec stream ended without an exit code: connection reset by peer" on
// Linode; not reproduced on loopback, where this passed before too).
func TestRelayDrainsTheClientAfterTheExit(t *testing.T) {
	const frames, size = 3, 32 << 10 // 96 KiB: the server's socket buffer holds what the client hasn't read
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var logs []string
	var lmu sync.Mutex
	srv := &Server{logf: func(f string, a ...any) { lmu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); lmu.Unlock() }}
	relayed := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		agentSide, agent := net.Pipe()
		go func() { // the host: the whole output and the exit code at once, then it's done
			chunk := []byte(strings.Repeat("x", size))
			for range frames {
				_ = client.WriteFrame(agent, client.FrameStdout, chunk)
			}
			_ = client.WriteFrame(agent, client.FrameExit, []byte{0, 0, 0, 7})
			_ = agent.Close()
		}()
		srv.relay(c, bufio.NewReader(c), agentSide, client.MaxFileTransfer, "dev/web on hv1 (ls)")
		close(relayed)
	}()
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error { // a slow reader: a small window
		return c.Control(func(fd uintptr) { _ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096) })
	}}
	cli, err := d.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	time.Sleep(300 * time.Millisecond) // the host is done, its tail queued on the server; the client hasn't read or sent yet
	if err := client.WriteFrame(cli, client.FrameStdinClose, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // a reset, if any, has arrived
	var out strings.Builder
	code, err := client.ReadOutput(cli, &out, nil)
	if err != nil || code != 7 || out.Len() != frames*size {
		t.Fatalf("exit %d, %d bytes, %v", code, out.Len(), err)
	}
	_ = cli.Close()
	select {
	case <-relayed:
	case <-time.After(streamDrain + 2*time.Second):
		t.Fatal("the relay didn't end once the client closed")
	}
	lmu.Lock()
	defer lmu.Unlock()
	if len(logs) != 0 {
		t.Errorf("a clean stream was logged: %v", logs)
	}
}

// A host stream that ends without an exit code is logged: no client may be there to hear of it.
func TestRelayLogsAStreamCutShort(t *testing.T) {
	cli, srvSide := net.Pipe()
	agentSide, agent := net.Pipe()
	var logs []string
	var lmu sync.Mutex
	srv := &Server{logf: func(f string, a ...any) { lmu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); lmu.Unlock() }}
	old := streamDrain
	streamDrain = 100 * time.Millisecond
	defer func() { streamDrain = old }()
	done := make(chan struct{})
	go func() {
		srv.relay(srvSide, bufio.NewReader(srvSide), agentSide, 0, "dev/web on hv1 (tar)")
		_ = srvSide.Close()
		close(done)
	}()
	go func() {
		_ = client.WriteFrame(agent, client.FrameStdout, []byte("part"))
		_ = agent.Close()
	}()
	if _, err := client.ReadOutput(cli, nil, nil); err == nil {
		t.Fatal("no error for a stream with no exit code")
	}
	<-done
	lmu.Lock()
	defer lmu.Unlock()
	if len(logs) != 1 || !strings.Contains(logs[0], "dev/web on hv1 (tar): ended early: the host's stream ended without an exit code (4 bytes to the client") {
		t.Fatalf("logs: %q", logs)
	}
}

// writeFails is a host stream that takes no more input but still sends its output.
type writeFails struct{ net.Conn }

func (writeFails) Write([]byte) (int, error) { return 0, net.ErrClosed }

// The host's side not taking input (stdin to a command that's done with it) doesn't end the
// stream: its output and exit code still reach the client. Before, either way ending ended the
// relay, and the rest of the output was cut off without a word.
func TestRelayKeepsTheOutputWhenInputCantGo(t *testing.T) {
	for _, limit := range []int64{0, client.MaxFileTransfer} {
		cli, srvSide := net.Pipe()
		agentSide, agent := net.Pipe()
		done := make(chan struct{})
		go func() {
			(&Server{}).relay(srvSide, bufio.NewReader(srvSide), writeFails{agentSide}, limit, "dev/web on hv1 (tar)")
			_ = srvSide.Close()
			close(done)
		}()
		_ = client.WriteFrame(cli, client.FrameStdinClose, nil) // can't go on: the stream takes no input
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = client.WriteFrame(agent, client.FrameStdout, []byte("all of it"))
			_ = client.WriteFrame(agent, client.FrameExit, []byte{0, 0, 0, 0})
			_ = agent.Close()
		}()
		var out strings.Builder
		code, err := client.ReadOutput(cli, &out, nil)
		if err != nil || code != 0 || out.String() != "all of it" {
			t.Fatalf("limit %d: exit %d, %q, %v", limit, code, out.String(), err)
		}
		_ = cli.Close()
		<-done
	}
}
