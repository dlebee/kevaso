package apiserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/pki"
)

// Component is kevasod's own controllers, heartbeat, worker and agent, talking to the API server
// in the same process. They used to share the admin socket, which made their constant traffic
// look like root's; now the admin socket is only for people (and audited), and this identity is
// reachable only from inside the process.
var Component = pki.Identity{Type: "component", Name: "kevasod", Role: "control-plane"}

// InProcess returns a client for kevasod's own components: an in-memory connection, no socket or
// port, authenticated as Component. Close the returned function when done. wrap, if given, wraps
// the handler (the control plane stamps the answers its worker judges, §0.7).
func (s *Server) InProcess(wrap ...func(http.Handler) http.Handler) (*client.Client, func()) {
	return s.inProcess(func(ctx context.Context) context.Context { return context.WithValue(ctx, componentConnKey, true) }, wrap...)
}

// InProcessAs is InProcess authenticated as id instead of Component: the worker on a system
// node, as its host (a worker), so what it writes is judged as a worker-only host's writes are
// (moves.HostWrite, the Host status checks), never with the control plane's own trust.
func (s *Server) InProcessAs(id pki.Identity, wrap ...func(http.Handler) http.Handler) (*client.Client, func()) {
	return s.inProcess(func(ctx context.Context) context.Context { return context.WithValue(ctx, inProcessIDKey, id) }, wrap...)
}

func (s *Server) inProcess(conn func(context.Context) context.Context, wrap ...func(http.Handler) http.Handler) (*client.Client, func()) {
	l := &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
	var h http.Handler = s
	for _, w := range wrap {
		h = w(h)
	}
	hs := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       func(ctx context.Context, _ net.Conn) context.Context { return conn(ctx) },
	}
	go func() { _ = hs.Serve(l) }()
	c := client.New("http://kevasod")
	c.HTTP = &http.Client{Transport: &http.Transport{DialContext: l.dial, ForceAttemptHTTP2: false}}
	return c, func() { _ = hs.Close() }
}

// pipeListener hands out the server ends of in-memory connections.
type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	c, s := net.Pipe()
	select {
	case l.conns <- s:
		return c, nil
	case <-l.done:
		return nil, errors.New("in-process API closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "in-process" }
