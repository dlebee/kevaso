package apiserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"kevaso.com/core/api/client"
)

// streamDrain is how long, once everything for the client is written, the client's side is still
// read (and discarded) waiting for it to close first.
var streamDrain = 5 * time.Second

// relay relays the frames of one silo stream between a client (conn, read through cr) and the
// silo's host (stream, over its tunnel), until the silo's side is over; with limit > 0, each way's
// data is capped and the first way over it gets an error frame and ends the stream.
//
// The stream ends from the silo's side: once its last frame (the exit code, or an error) is
// relayed, the client's connection is half-closed (TLS close_notify: the client reads EOF after
// it) and what the client still sends (its stdin close, more stdin a command didn't read) is read
// and dropped until it closes, or for streamDrain. Closing a socket with unread bytes, or that
// bytes arrive at, makes the kernel send a reset instead, and a client that gets one may lose the
// frames it hadn't read yet: "exec stream ended without an exit code: connection reset by peer"
// (macOS drops the unread data). A stream that ends any other way is logged, with what got
// through, since no client may be there to hear of it.
func (s *Server) relay(conn net.Conn, cr *bufio.Reader, stream net.Conn, limit int64, what string) {
	var (
		mu         sync.Mutex // writes to conn
		up, down   atomic.Int64
		forward    atomic.Bool // client → silo still forwarded
		lastToConn atomic.Uint32
	)
	forward.Store(true)
	over := func(way string) {
		mu.Lock()
		defer mu.Unlock()
		_ = client.WriteFrame(conn, client.FrameError, fmt.Appendf(nil, "%s is over the %d byte limit of one transfer", way, limit))
		lastToConn.Store(uint32(client.FrameError))
	}
	clientDone := make(chan error, 1) // the client closed (or the drain ran out)
	upOver := make(chan struct{}, 1)
	go func() { // client → silo; once the silo's side is over, only drained
		for {
			typ, p, err := client.ReadFrame(cr)
			if err != nil {
				clientDone <- err
				return
			}
			if !forward.Load() {
				continue
			}
			if typ == client.FrameStdin {
				if n := up.Add(int64(len(p))); limit > 0 && n > limit {
					forward.Store(false)
					over("the upload")
					upOver <- struct{}{}
					continue
				}
			}
			if client.WriteFrame(stream, typ, p) != nil {
				forward.Store(false) // the silo's side is gone: keep draining
			}
		}
	}()
	siloDone := make(chan error, 1)
	go func() { // silo → client
		br := bufio.NewReader(stream)
		for {
			typ, p, err := client.ReadFrame(br)
			if err != nil {
				siloDone <- err
				return
			}
			if typ == client.FrameStdout || typ == client.FrameStderr {
				if n := down.Add(int64(len(p))); limit > 0 && n > limit {
					over("the download")
					siloDone <- nil
					return
				}
			}
			mu.Lock()
			err = client.WriteFrame(conn, typ, p)
			mu.Unlock()
			if err != nil {
				siloDone <- fmt.Errorf("writing to the client: %w", err)
				return
			}
			lastToConn.Store(uint32(typ))
		}
	}()
	logEnd := func(why string, err error) {
		s.log("silo stream %s: %s: %v (%d bytes to the client, %d from it)", what, why, err, down.Load(), up.Load())
	}
	select {
	case err := <-clientDone:
		// The client went away first: closing the stream stops the command in the silo.
		if !quietEnd(err) {
			logEnd("the client's side broke", err)
		}
		return
	case <-upOver:
	case err := <-siloDone:
		if last := byte(lastToConn.Load()); last != client.FrameExit && last != client.FrameError {
			if err == nil || errors.Is(err, io.EOF) {
				err = errors.New("the host's stream ended without an exit code")
			}
			logEnd("ended early", err)
		}
	}
	forward.Store(false)
	_ = stream.Close()
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(streamDrain))
	<-clientDone
}

// quietEnd: how a client normally leaves (closed, or gone with its connection).
func quietEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded)
}
