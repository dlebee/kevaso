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

// An upgrade's answer (a tunnel, an exec stream) is a transport, not state to apply: without a
// stamp it is handed over unjudged (a control plane that ever loses the stamp on a hijacked answer
// doesn't cut every agent's tunnel), and nothing kept changes. With one it is judged: a worker
// that is held, or an answer of another cluster, takes no stream (no work through it) until that
// ends.
func TestAnUpgradesAnswerIsJudgedOnlyWhenStamped(t *testing.T) {
	short(t)
	var stampWith *ControlPlaneSeen
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		h := http.Header{}
		if stampWith != nil {
			SetControlPlane(h, *stampWith)
		}
		h.Set("Upgrade", "echo")
		h.Set("Connection", "Upgrade")
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
		_ = h.Write(rw)
		_, _ = rw.WriteString("\r\n")
		_ = rw.Flush()
		_, _ = io.Copy(conn, rw)
	}))
	defer ts.Close()
	ctx := context.Background()
	open := func(kept Watermark) (*verdicts, error) {
		c, err := NewTLSEndpoints([]string{ts.URL}, caOf(ts), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		j := &verdicts{kept: kept}
		c.ControlPlane = j
		s, err := c.Upgrade(ctx, http.MethodGet, "/agent/connect", "echo", nil)
		if err == nil {
			_ = s.Close()
		}
		return j, err
	}
	kept := Watermark{ClusterID: "c", History: "h", Epoch: 1, Revision: 100}

	stampWith = nil
	if j, err := open(kept); err != nil || len(j.got) != 0 || j.kept != kept {
		t.Fatalf("unstamped: %v, judged %v, kept %+v; want handed over, unjudged, nothing kept changed", err, j.got, j.kept)
	}
	stampWith = &ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 120}
	if j, err := open(kept); err != nil || j.kept.Revision != 120 {
		t.Fatalf("stamped, healthy: %v, kept %+v", err, j.kept)
	}
	stampWith = &ControlPlaneSeen{ClusterID: "c", History: "h", Epoch: 1, Revision: 50}
	if _, err := open(kept); !IsHeld(err) {
		t.Fatalf("stamped, older than what was kept (held): %v, want refused as held", err)
	}
	stampWith = &ControlPlaneSeen{ClusterID: "other", History: "x", Epoch: 1, Revision: 900}
	if _, err := open(kept); !IsHeld(err) {
		t.Fatalf("stamped, another cluster: %v, want refused", err)
	}
}
