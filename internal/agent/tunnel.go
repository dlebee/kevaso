package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"kevaso.com/core/api/client"
	"kevaso.com/core/sdk/kri"
)

// RunTunnel keeps a connection open to the control plane (research E020: agents dial out, so
// hosts need no inbound port) and serves the exec streams the API server opens on it.
func (a *Agent) RunTunnel(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.tunnelOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // it was up for a while: reconnect quickly
		}
		a.log("tunnel: %v (reconnecting in %v)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (a *Agent) tunnelOnce(ctx context.Context) error {
	conn, err := a.Client.Upgrade(ctx, http.MethodGet, "/agent/connect?host="+url.QueryEscape(a.HostName), "kevaso-tunnel", nil)
	if err != nil {
		return err
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	sess, err := yamux.Server(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = sess.Close() }()
	go func() { <-ctx.Done(); _ = sess.Close() }()
	for {
		st, err := sess.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) || sess.IsClosed() {
				return errors.New("connection closed")
			}
			return err
		}
		go a.serveExec(ctx, st)
	}
}

// serveExec runs one exec stream: a JSON header line, then frames both ways.
func (a *Agent) serveExec(ctx context.Context, st net.Conn) {
	defer func() { _ = st.Close() }()
	br := bufio.NewReader(st)
	var mu sync.Mutex
	fail := func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		_ = client.WriteFrame(st, client.FrameError, []byte(msg))
	}
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var h client.ExecHeader
	if err := json.Unmarshal(line, &h); err != nil || len(h.Command) == 0 {
		fail("bad exec header")
		return
	}
	rt, ok := a.Runtimes[h.Runtime]
	if !ok {
		fail("runtime " + h.Runtime + " isn't on host " + a.HostName)
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pr, pw := io.Pipe()
	go func() { // stdin frames → the command; the stream ending ends the command
		defer cancel()
		for {
			typ, p, err := client.ReadFrame(br)
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			switch typ {
			case client.FrameStdin:
				if _, err := pw.Write(p); err != nil {
					// the command stopped reading; keep draining for FrameStdinClose
					continue
				}
			case client.FrameStdinClose:
				_ = pw.Close()
				// keep reading: EOF on the stream means the client went away
				if _, _, err := client.ReadFrame(br); err != nil {
					return
				}
			}
		}
	}()
	id := kri.ID{Namespace: h.Namespace, Name: h.Name, UID: h.UID}
	code, err := rt.Exec(ctx, id, kri.ExecRequest{
		Command: h.Command,
		Stdin:   pr,
		Stdout:  client.FrameWriter{W: st, Typ: client.FrameStdout, Mu: &mu},
		Stderr:  client.FrameWriter{W: st, Typ: client.FrameStderr, Mu: &mu},
	})
	_ = pr.Close()
	if err != nil {
		fail(err.Error())
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(code)))
	mu.Lock()
	_ = client.WriteFrame(st, client.FrameExit, b[:])
	mu.Unlock()
}
