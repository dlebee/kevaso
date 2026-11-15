package client

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// An upgraded stream (exec, terminal, port-forward, kvo cp) through a client with several system
// nodes (NewTLSEndpoints, as kvo and the agents make it) is the raw connection: writable, and not
// cut by the attempt deadline (K-008 wrapped the answer's body, hiding Write: "server switched
// protocols but the stream isn't writable" on the soak cluster).
func TestAnUpgradedStreamThroughTheFailoverClientIsWritableAndOutlivesTheDeadline(t *testing.T) {
	short(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "want an upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw) // echo everything back
	}))
	defer ts.Close()
	c, err := NewTLSEndpoints([]string{ts.URL}, caOf(ts), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Upgrade(ctx, http.MethodPost, "/x", "echo", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	rd := bufio.NewReader(s)
	for i, msg := range []string{"one\n", "two\n"} {
		if i == 1 {
			// Longer than the attempt deadline: a stream is bounded by its dial and headers only.
			select {
			case <-time.After(3 * AttemptTimeout):
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		if _, err := io.WriteString(s, msg); err != nil {
			t.Fatalf("write %q: %v", msg, err)
		}
		got, err := rd.ReadString('\n')
		if err != nil || got != msg {
			t.Fatalf("echo of %q: %q %v", msg, got, err)
		}
	}
}
