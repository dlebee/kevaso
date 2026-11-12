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
// port, authenticated as Component. Close the returned function when done.
func (s *Server) InProcess() (*client.Client, func()) {
	l := &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, componentConnKey, true)
		},
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
