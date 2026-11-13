// Package siloui is `kvo ui silo NAME` (design §10): a small page for one silo, served by kvo on
// 127.0.0.1, with a terminal and a file explorer. kvo holds the API session; the page only talks
// to kvo, on the same exec streams as kvo ssh and kvo cp.
//
// Nothing listens beyond loopback. The URL kvo opens carries a one-time token, swapped on first
// use for a session cookie (HttpOnly, SameSite=Strict, named after the port); every request must
// name this server as its Host (no DNS rebinding) and, if it has an Origin, this server's origin;
// every request that changes something, and every WebSocket, must have that Origin.
package siloui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"kevaso.com/core/internal/transfer"
)

//go:embed static
var static embed.FS

// Server is one silo's page.
type Server struct {
	Silo transfer.Silo

	mu      sync.Mutex
	token   string // in the URL, good once
	used    bool
	session string // the cookie's value
	host    string // 127.0.0.1:PORT
	origin  string // http://127.0.0.1:PORT
	cookie  string
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Listen picks a random port on 127.0.0.1 and returns the URL to open (with its token).
func (s *Server) Listen() (net.Listener, string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = l.Addr().String()
	s.origin = "http://" + s.host
	s.cookie = "kvo_ui_" + strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	s.token, s.session, s.used = random(), random(), false
	return l, s.origin + "/?token=" + s.token, nil
}

// Serve serves the page on l until ctx ends (kvo exits); then every terminal is closed, which
// stops its shell in the silo.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws://"+s.host+"; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.Host != s.host {
		http.Error(w, "wrong host", http.StatusMisdirectedRequest)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && origin != s.origin {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	ws := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if (ws || (r.Method != http.MethodGet && r.Method != http.MethodHead)) && origin != s.origin {
		http.Error(w, "this needs the page's own origin", http.StatusForbidden)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/" && r.URL.Query().Has("token") {
		s.redeem(w, r)
		return
	}
	if !s.authenticated(r) {
		http.Error(w, "open the link kvo ui printed (it works once); run kvo ui again for a new one", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/" && r.Method == http.MethodGet:
		serveFile(w, "static/index.html", "text/html; charset=utf-8")
	case strings.HasPrefix(r.URL.Path, "/static/") && r.Method == http.MethodGet:
		s.serveStatic(w, r)
	case r.URL.Path == "/api/info" && r.Method == http.MethodGet:
		writeJSON(w, map[string]string{"namespace": s.Silo.Namespace, "name": s.Silo.Name})
	case r.URL.Path == "/api/list" && r.Method == http.MethodGet:
		s.list(w, r)
	case r.URL.Path == "/api/download" && r.Method == http.MethodGet:
		s.download(w, r)
	case r.URL.Path == "/api/upload" && r.Method == http.MethodPost:
		s.upload(w, r)
	case r.URL.Path == "/ws/terminal" && ws:
		s.terminal(w, r)
	default:
		http.NotFound(w, r)
	}
}

// redeem swaps the URL's one-time token for the session cookie, and drops the token from the
// address bar.
func (s *Server) redeem(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	ok := !s.used && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(s.token)) == 1
	if ok {
		s.used = true
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "this link was used already, or is wrong: run kvo ui again for a new one", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) authenticated(r *http.Request) bool {
	c, err := r.Cookie(s.cookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session)) == 1
}

func serveFile(w http.ResponseWriter, name, typ string) {
	b, err := static.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", typ)
	_, _ = w.Write(b)
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	name := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if !fs.ValidPath(name) || !strings.HasPrefix(name, "static/") {
		http.NotFound(w, r)
		return
	}
	typ := map[string]string{".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}[path.Ext(name)]
	if typ == "" {
		http.NotFound(w, r) // licenses and notes stay in the repo
		return
	}
	serveFile(w, name, typ)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func siloPath(r *http.Request, key string) (string, error) {
	p := r.URL.Query().Get(key)
	if !path.IsAbs(p) {
		return "", fmt.Errorf("%s: want an absolute path in the silo", key)
	}
	return path.Clean(p), nil
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	p, err := siloPath(r, "path")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	es, err := s.Silo.List(r.Context(), p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if es == nil {
		es = []transfer.Entry{}
	}
	writeJSON(w, map[string]any{"path": p, "entries": es})
}

// download sends a file as itself, or a folder as a tar.
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	p, err := siloPath(r, "path")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e, ok, err := s.Silo.Stat(r.Context(), p)
	if err != nil || !ok {
		http.Error(w, fmt.Sprint("no such file: ", p, " ", err), http.StatusNotFound)
		return
	}
	base := path.Base(p)
	if p == "/" {
		base = s.Silo.Name
	}
	if e.Type == "dir" {
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", disposition(base+".tar"))
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		cw := &capWriter{w: w, left: s.limit(), over: cancel}
		if err := s.Silo.ReadTar(ctx, p, cw); err != nil || cw.err != nil {
			abort(w)
		}
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", disposition(base))
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := transfer.FirstFile(pr, w, s.limit())
		_, _ = io.Copy(io.Discard, pr)
		done <- err
	}()
	err = s.Silo.ReadTar(r.Context(), p, pw)
	_ = pw.CloseWithError(err)
	if ferr := <-done; err != nil || ferr != nil {
		abort(w)
	}
}

func (s *Server) limit() int64 {
	if s.Silo.Limit > 0 {
		return s.Silo.Limit
	}
	return transfer.DefaultLimit
}

// abort breaks a response already under way, so the browser sees a failed download rather than a
// short file.
func abort(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			_ = c.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

// capWriter passes on at most left bytes; past that, or if the page stops reading, it stops the
// download (over) and keeps the error.
type capWriter struct {
	w    io.Writer
	left int64
	over func()
	err  error
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if int64(len(p)) > c.left {
		c.err = transfer.ErrTooBig
	} else if _, err := c.w.Write(p); err != nil {
		c.err = err
	}
	if c.err != nil {
		c.over()
		return 0, c.err
	}
	c.left -= int64(len(p))
	return len(p), nil
}

func disposition(name string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return '_'
		}
		return r
	}, name)
	return `attachment; filename="` + safe + `"`
}

// upload writes the request's body as dir/name in the silo.
func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	dir, err := siloPath(r, "dir")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := r.URL.Query().Get("name")
	if r.ContentLength < 0 {
		http.Error(w, "an upload needs its length", http.StatusLengthRequired)
		return
	}
	if r.ContentLength > s.limit() {
		http.Error(w, fmt.Sprintf("%d bytes is over the %d byte limit", r.ContentLength, s.limit()), http.StatusRequestEntityTooLarge)
		return
	}
	err = s.Silo.WriteTar(r.Context(), dir, func(tw io.Writer) error {
		return transfer.OneFile(tw, name, r.ContentLength, r.Body)
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"path": path.Join(dir, name), "size": r.ContentLength})
}

// terminal is a login shell (kvo ssh) on a WebSocket: binary messages are keystrokes one way and
// output the other; text messages are JSON: {"resize":[rows,cols]} from the page, {"exit":code} or
// {"error":"…"} to it, just before kvo closes the socket.
func (s *Server) terminal(w http.ResponseWriter, r *http.Request) {
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	c, err := websocket.Accept(w, r, nil) // checks the Origin against the Host too
	if err != nil {
		return
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sess, err := s.Silo.C.OpenShell(ctx, s.Silo.Namespace, s.Silo.Name, clamp(rows, 24), clamp(cols, 80))
	if err != nil {
		_ = c.Write(ctx, websocket.MessageText, mustJSON(map[string]string{"error": err.Error()}))
		_ = c.Close(websocket.StatusNormalClosure, "")
		return
	}
	defer func() { _ = sess.Close() }() // the page went away: the shell is stopped in the silo
	go func() {
		defer cancel()
		for {
			typ, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			if typ == websocket.MessageBinary {
				if _, err := sess.Write(b); err != nil {
					return
				}
				continue
			}
			var m struct {
				Resize []int `json:"resize"`
			}
			if json.Unmarshal(b, &m) == nil && len(m.Resize) == 2 {
				_ = sess.Resize(clamp(m.Resize[0], 24), clamp(m.Resize[1], 80))
			}
		}
	}()
	code, err := sess.Wait(wsWriter{ctx, c}, wsWriter{ctx, c})
	msg := map[string]any{"exit": code}
	if err != nil {
		msg = map[string]any{"error": err.Error()}
	}
	_ = c.Write(ctx, websocket.MessageText, mustJSON(msg))
	_ = c.Close(websocket.StatusNormalClosure, "")
}

type wsWriter struct {
	ctx context.Context
	c   *websocket.Conn
}

func (w wsWriter) Write(p []byte) (int, error) {
	if err := w.c.Write(w.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func clamp(v, def int) uint16 {
	if v <= 0 || v > 1000 {
		return uint16(def)
	}
	return uint16(v)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
