package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Toward several system nodes (K-008, brainstorm §0.7): a node that went silent, never answers,
// or answers without a store quorum must not hold a worker's requests. The client gives each
// attempt a deadline for its answer to begin, finds dead HTTP/2 connections by pinging, and goes
// on to the next system node when it can safely. A worker that reaches no healthy node keeps its
// last state; the point is never to spin and never to block its loop.
var (
	// AttemptTimeout is how long one attempt waits for its answer to begin (its headers), on a
	// client with several system nodes (NewTLSEndpoints). Well under the agents' 10 s heartbeat.
	// A call known to take longer before answering passes Patient(ctx).
	AttemptTimeout = 6 * time.Second
	// PingAfter and PingTimeout: an HTTP/2 connection quiet for PingAfter is pinged, and closed
	// when no answer comes within PingTimeout (a watch on it ends; the informer lists again).
	PingAfter   = 5 * time.Second
	PingTimeout = 5 * time.Second
)

// HeaderUnavailable is set on a 503 a system node gives before handling anything, because its
// store can't serve (no quorum, or not answering): the request may go to another node as it is.
const HeaderUnavailable = "Kevaso-Unavailable"

// WriteUnavailable is that answer (the control plane's side).
func WriteUnavailable(w http.ResponseWriter, why string) {
	w.Header().Set(HeaderUnavailable, why)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"code":503,"reason":"Unavailable","message":` + strconv.Quote("this system node can't serve: "+why+"; try another") + `}`))
}

// IsUnavailable reports a system node that couldn't serve (WriteUnavailable): every one asked.
func IsUnavailable(err error) bool { return reasonOf(err) == "Unavailable" }

// IsTimeout reports a request that got no answer in time (AttemptTimeout, or the caller's own
// deadline).
func IsTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

type patientKey struct{}

// Patient marks a call that may take longer than AttemptTimeout before its answer begins (a
// system node's join, which waits for its store to catch up): no attempt deadline.
func Patient(ctx context.Context) context.Context { return context.WithValue(ctx, patientKey{}, true) }

// errAttempt is an attempt that got no answer within AttemptTimeout.
type errAttempt struct{ host string }

func (e errAttempt) Error() string {
	return "no answer from " + e.host + " within " + AttemptTimeout.String()
}
func (errAttempt) Timeout() bool   { return true }
func (errAttempt) Temporary() bool { return true }

// replayable: a request another node may be sent after one that didn't answer: it can't apply
// twice (a read; a PUT, which carries the resourceVersion it was read at: a second send
// conflicts).
func replayable(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPut
}

// attempt sends r with AttemptTimeout for its answer to begin (unless the call is Patient). The
// answer's body, once it has begun, is read on the caller's own deadline.
func attempt(base http.RoundTripper, r *http.Request) (*http.Response, error) {
	if v, _ := r.Context().Value(patientKey{}).(bool); v || AttemptTimeout <= 0 {
		return base.RoundTrip(r)
	}
	ctx, cancel := context.WithCancel(r.Context())
	t := time.AfterFunc(AttemptTimeout, cancel)
	resp, err := base.RoundTrip(r.WithContext(ctx))
	if !t.Stop() { // it fired: whatever came back came too late
		if resp != nil {
			_ = resp.Body.Close()
		}
		cancel()
		if r.Context().Err() != nil {
			return nil, r.Context().Err()
		}
		return nil, errAttempt{host: r.URL.Host}
	}
	if err != nil {
		cancel()
		return nil, err
	}
	if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
		// An upgraded stream (101: exec, terminal, port-forward, kvo cp): the raw connection,
		// which must stay writable (Upgrade needs its Write); bounded by the dial and the headers
		// only, never by AttemptTimeout.
		resp.Body = &cancelOnCloseRW{ReadWriteCloser: rw, cancel: cancel}
		return resp, nil
	}
	resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelOnCloseRW struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (c *cancelOnCloseRW) Close() error {
	err := c.ReadWriteCloser.Close()
	c.cancel()
	return err
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// unavailable: a system node said it can't serve before handling anything (WriteUnavailable).
func unavailable(resp *http.Response) bool {
	return resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get(HeaderUnavailable) != ""
}
