package apiserver

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/yamux"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/store"
)

// Agents dial out to the control plane and keep one connection open (research E020): the API
// server opens a multiplexed stream on it for each `kvo exec`, so hosts need no inbound port and
// can sit behind NAT.
//
//	GET  /agent/connect?host=NAME                         (Upgrade: kevaso-tunnel) an agent registers
//	POST /apis/kevaso/v1/namespaces/NS/silos/NAME/exec    (Upgrade: kevaso-exec)   relayed to that host

type tunnels struct {
	mu   sync.Mutex
	sess map[string]*yamux.Session
}

func (t *tunnels) set(host string, s *yamux.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.sess[host]; ok && old != s {
		_ = old.Close() // a reconnect replaces the old session
	}
	t.sess[host] = s
}

func (t *tunnels) drop(host string, s *yamux.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sess[host] == s {
		delete(t.sess, host)
	}
}

func (t *tunnels) get(host string) *yamux.Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.sess[host]
	if s != nil && s.IsClosed() {
		delete(t.sess, host)
		return nil
	}
	return s
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard
	return c
}

// hijack answers 101 Switching Protocols and returns the raw connection.
func hijack(w http.ResponseWriter, proto string) (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errf(http.StatusHTTPVersionNotSupported, "HTTPVersionNotSupported", "streams need HTTP/1.1")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + proto + "\r\nConnection: Upgrade\r\n\r\n")
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, rw, nil
}

// bufConn reads through the hijack's buffered reader (it may hold bytes already).
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// agentConnect: a host's agent registers its tunnel. A host certificate may register only itself;
// the local admin socket (the in-process agent) may register its host.
func (s *Server) agentConnect(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" || !strings.EqualFold(r.Header.Get("Upgrade"), "kevaso-tunnel") {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "want Upgrade: kevaso-tunnel and ?host="))
		return
	}
	if s.auth != nil {
		id, _ := IdentityFrom(r.Context())
		if id != LocalAdmin && (id.Type != "host" || id.Name != host) {
			writeErr(w, errf(http.StatusForbidden, "Forbidden", "%s may not connect as host %s", id, host))
			return
		}
	}
	conn, rw, err := hijack(w, "kevaso-tunnel")
	if err != nil {
		writeErr(w, err)
		return
	}
	// The control plane is the yamux client: it opens streams into the agent.
	sess, err := yamux.Client(bufConn{Conn: conn, r: rw.Reader}, yamuxConfig())
	if err != nil {
		_ = conn.Close()
		return
	}
	s.tunnels.set(host, sess)
	<-sess.CloseChan()
	s.tunnels.drop(host, sess)
}

// siloExec relays a `kvo exec` to the silo's host over its agent's tunnel.
func (s *Server) siloExec(w http.ResponseWriter, r *http.Request, ns, name string) {
	// authorize (in wrap) already allowed only cluster admins and control-plane hosts.
	if r.Method != http.MethodPost || !strings.EqualFold(r.Header.Get("Upgrade"), "kevaso-exec") {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "want POST with Upgrade: kevaso-exec"))
		return
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req client.ExecRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Command) == 0 {
		writeErr(w, errf(http.StatusBadRequest, "BadRequest", "body: want {\"command\": [...]}"))
		return
	}
	o, err := s.store.Get(r.Context(), store.Key{Kind: "Silo", Namespace: ns, Name: name})
	if err != nil {
		writeErr(w, err)
		return
	}
	obj, _, err := v1.Decode(o.Data)
	if err != nil {
		writeErr(w, err)
		return
	}
	silo := obj.(*v1.Silo)
	if silo.Status.Host == "" {
		writeErr(w, errf(http.StatusConflict, "NotScheduled", "silo %s/%s isn't on a host yet", ns, name))
		return
	}
	sess := s.tunnels.get(silo.Status.Host)
	if sess == nil {
		writeErr(w, errf(http.StatusServiceUnavailable, "HostNotConnected", "host %s's agent isn't connected", silo.Status.Host))
		return
	}
	stream, err := sess.Open()
	if err != nil {
		writeErr(w, errf(http.StatusServiceUnavailable, "HostNotConnected", "host %s: %v", silo.Status.Host, err))
		return
	}
	defer func() { _ = stream.Close() }()
	hdr, _ := json.Marshal(client.ExecHeader{Namespace: ns, Name: name, UID: silo.UID, Runtime: silo.Spec.Runtime, Command: req.Command})
	if _, err := stream.Write(append(hdr, '\n')); err != nil {
		writeErr(w, err)
		return
	}
	conn, rw, err := hijack(w, "kevaso-exec")
	if err != nil {
		writeErr(w, err)
		return
	}
	defer func() { _ = conn.Close() }()
	// Both legs speak the same frames: relay bytes until either side is done.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stream, rw.Reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, stream); done <- struct{}{} }()
	<-done
}
