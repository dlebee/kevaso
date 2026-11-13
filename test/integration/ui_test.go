package integration

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/siloui"
	"kevaso.com/core/internal/transfer"
	"kevaso.com/core/sdk/kri/fake"
)

// kvo ui against the in-process cluster: the page's terminal and file explorer reach the silo.
func TestUIShellAndFiles(t *testing.T) {
	rt := fake.New()
	fs := &siloFS{files: map[string][]byte{"/srv/hello.txt": []byte("hi")}, dirs: map[string]bool{"/": true, "/srv": true, "/srv/sub": true}}
	rt.Program = fs.program(make(chan struct{}, 1))
	h, ctx, _ := runningSilo(t, rt)

	srv := &siloui.Server{Silo: transfer.Silo{C: client.New(h.server), Namespace: "demo", Name: "hello"}}
	l, link, err := srv.Listen()
	if err != nil {
		t.Fatal(err)
	}
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = srv.Serve(sctx, l) }()
	origin := "http://" + l.Addr().String()
	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar}
	if resp, err := b.Get(link); err != nil || resp.StatusCode != 200 {
		t.Fatalf("open the link: %v %v", resp, err)
	}
	req := func(method, path string, body io.Reader, n int64) (int, []byte) {
		t.Helper()
		r, _ := http.NewRequestWithContext(ctx, method, origin+path, body)
		r.Header.Set("Origin", origin)
		r.ContentLength = n
		resp, err := b.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, data
	}

	// The terminal: a login shell on a terminal of the page's size, then its exit code.
	hdr := http.Header{"Origin": {origin}}
	for _, c := range jar.Cookies(mustURL(t, origin)) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	ws, _, err := websocket.Dial(ctx, "ws://"+l.Addr().String()+"/ws/terminal?rows=40&cols=100", &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		t.Fatal(err)
	}
	var screen bytes.Buffer
	for {
		typ, msg, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("terminal: %v (screen %q)", err, screen.String())
		}
		if typ == websocket.MessageBinary {
			screen.Write(msg)
			continue
		}
		if string(msg) != `{"exit":0}` || screen.String() != "login shell, terminal true 40x100\n" {
			t.Fatalf("terminal: %s, screen %q", msg, screen.String())
		}
		break
	}
	_ = ws.CloseNow()

	// The explorer: list, upload, download a file, download a folder.
	code, data := req("GET", "/api/list?path=/srv", nil, 0)
	var list struct {
		Path    string
		Entries []transfer.Entry
	}
	if code != 200 || json.Unmarshal(data, &list) != nil || list.Path != "/srv" || len(list.Entries) != 2 {
		t.Fatalf("list: %d %s", code, data)
	}
	code, data = req("POST", "/api/upload?dir=/srv/sub&name=notes.md", strings.NewReader("# notes"), 7)
	if code != 200 {
		t.Fatalf("upload: %d %s", code, data)
	}
	fs.mu.Lock()
	got := string(fs.files["/srv/sub/notes.md"])
	fs.mu.Unlock()
	if got != "# notes" {
		t.Fatalf("uploaded: %q", got)
	}
	if code, data = req("GET", "/api/download?path=/srv/sub/notes.md", nil, 0); code != 200 || string(data) != "# notes" {
		t.Fatalf("download: %d %q", code, data)
	}
	code, data = req("GET", "/api/download?path=/srv/sub", nil, 0)
	if code != 200 {
		t.Fatalf("download a folder: %d", code)
	}
	tr := tar.NewReader(bytes.NewReader(data))
	var names []string
	for {
		hd, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, hd.Name)
	}
	if strings.Join(names, ",") != "./sub/,./sub/notes.md" {
		t.Fatalf("folder tar: %v", names)
	}
	if code, _ = req("GET", "/api/download?path=/srv/none", nil, 0); code != 404 {
		t.Fatalf("download of nothing: %d", code)
	}
	if code, _ = req("POST", "/api/upload?dir=/srv&name=../x", strings.NewReader("x"), 1); code == 200 {
		t.Fatal("an upload named ../x")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
