package siloui

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/transfer"
)

func start(t *testing.T) (*Server, string, context.CancelFunc) {
	t.Helper()
	// No API behind it: the checks under test come before any call to the cluster.
	s := &Server{Silo: transfer.Silo{C: client.New("http://127.0.0.1:1"), Namespace: "dev", Name: "web"}}
	l, link, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "http://127.0.0.1:") || !strings.Contains(link, "/?token=") {
		t.Fatalf("link %s", link)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("the server didn't stop with its context")
		}
	})
	return s, link, cancel
}

func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, c *http.Client, method, u string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokenIsGoodOnceAndBecomesACookie(t *testing.T) {
	s, link, _ := start(t)
	origin := s.origin
	b := browser(t)
	if code, _ := do(t, b, "GET", origin+"/api/info", nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	u, _ := url.Parse(link)
	if code, _ := do(t, b, "GET", origin+"/?token=wrong"+u.Query().Get("token"), nil); code != http.StatusForbidden {
		t.Fatalf("wrong token: %d", code)
	}
	code, _ := do(t, b, "GET", link, nil)
	if code != http.StatusSeeOther {
		t.Fatalf("the link: %d", code)
	}
	cs := b.Jar.Cookies(u)
	if len(cs) != 1 || !strings.HasPrefix(cs[0].Name, "kvo_ui_") {
		t.Fatalf("cookies %v", cs)
	}
	if code, body := do(t, b, "GET", origin+"/api/info", nil); code != 200 || !strings.Contains(body, `"name":"web"`) {
		t.Fatalf("with the cookie: %d %s", code, body)
	}
	if code, body := do(t, b, "GET", origin+"/", nil); code != 200 || !strings.Contains(body, "xterm.js") {
		t.Fatalf("the page: %d", code)
	}
	if code, _ := do(t, b, "GET", origin+"/static/vendor/xterm/xterm.js", nil); code != 200 {
		t.Fatalf("xterm.js: %d", code)
	}
	if code, _ := do(t, b, "GET", origin+"/static/vendor/xterm/LICENSE", nil); code != 404 {
		t.Fatalf("only scripts and styles are served: %d", code)
	}
	// Used once: another browser (or a second click) can't have it.
	if code, _ := do(t, browser(t), "GET", link, nil); code != http.StatusForbidden {
		t.Fatalf("the link a second time: %d", code)
	}
}

func TestHostAndOriginChecks(t *testing.T) {
	s, link, _ := start(t)
	b := browser(t)
	if code, _ := do(t, b, "GET", link, nil); code != http.StatusSeeOther {
		t.Fatal(code)
	}
	o := s.origin
	for _, c := range []struct {
		name   string
		method string
		path   string
		hdr    map[string]string
		want   int
	}{
		{"DNS rebinding", "GET", "/api/info", map[string]string{"Host": "evil.example:" + strings.TrimPrefix(o, "http://127.0.0.1:")}, http.StatusMisdirectedRequest},
		{"localhost isn't our host", "GET", "/api/info", map[string]string{"Host": "localhost"}, http.StatusMisdirectedRequest},
		{"another origin", "GET", "/api/list?path=/", map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden},
		{"another local port", "GET", "/api/info", map[string]string{"Origin": "http://127.0.0.1:1"}, http.StatusForbidden},
		{"cross-site fetch", "GET", "/api/info", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"upload without an origin", "POST", "/api/upload?dir=/tmp&name=x", nil, http.StatusForbidden},
		{"upload from another origin", "POST", "/api/upload?dir=/tmp&name=x", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"same origin", "GET", "/api/info", map[string]string{"Origin": o, "Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"relative path", "GET", "/api/list?path=etc", nil, http.StatusBadRequest},
	} {
		if code, body := do(t, b, c.method, o+c.path, c.hdr); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.want)
		}
	}
	// A WebSocket needs the page's origin; with it, the terminal opens (and says the cluster
	// isn't there, since this test has none).
	u, _ := url.Parse(o)
	hdr := http.Header{}
	for _, c := range b.Jar.Cookies(u) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws := "ws://" + s.host + "/ws/terminal?rows=24&cols=80"
	for _, bad := range []string{"", "http://evil.example"} {
		h := hdr.Clone()
		if bad != "" {
			h.Set("Origin", bad)
		}
		if _, resp, err := websocket.Dial(ctx, ws, &websocket.DialOptions{HTTPHeader: h}); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("WebSocket with origin %q: %v", bad, err)
		}
	}
	h := hdr.Clone()
	h.Set("Origin", o)
	c, _, err := websocket.Dial(ctx, ws, &websocket.DialOptions{HTTPHeader: h})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	typ, msg, err := c.Read(ctx)
	if err != nil || typ != websocket.MessageText || !strings.Contains(string(msg), `"error"`) {
		t.Fatalf("%v %s %v", typ, msg, err)
	}
	// And no cookie, no WebSocket.
	if _, resp, err := websocket.Dial(ctx, ws, &websocket.DialOptions{HTTPHeader: http.Header{"Origin": {o}}}); err == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("WebSocket without the cookie: %v", err)
	}
}

func TestListensOnLoopbackOnly(t *testing.T) {
	s, _, _ := start(t)
	if !strings.HasPrefix(s.host, "127.0.0.1:") {
		t.Fatalf("listening on %s", s.host)
	}
}
