package client

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// silentProxy forwards TCP to a server until frozen; then it goes silent both ways without
// closing anything (a system node that lost power or its network: no RST, nothing).
type silentProxy struct {
	l      net.Listener
	frozen atomic.Bool
	gone   chan struct{}
	once   sync.Once
}

func newSilentProxy(t *testing.T, to string) *silentProxy {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &silentProxy{l: l, gone: make(chan struct{})}
	t.Cleanup(func() { p.once.Do(func() { close(p.gone) }); _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", to)
			if err != nil {
				_ = c.Close()
				continue
			}
			go p.pipe(c, s)
			go p.pipe(s, c)
		}
	}()
	return p
}

func (p *silentProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if p.frozen.Load() {
			<-p.gone // swallow it, and everything after, until the test ends
			_, _ = src.Close(), dst.Close()
			return
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

func (p *silentProxy) url() string { return "https://" + p.l.Addr().String() }

func h2Server(t *testing.T, h http.HandlerFunc) *httptest.Server {
	ts := httptest.NewUnstartedServer(h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// short sets the client's timeouts short for a test (restored after).
func short(t *testing.T) {
	a, s, p := AttemptTimeout, PingAfter, PingTimeout
	AttemptTimeout, PingAfter, PingTimeout = 300*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { AttemptTimeout, PingAfter, PingTimeout = a, s, p })
}

func caOf(ts *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
}

func whoami(name string, hits *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"type":"user","name":"` + name + `"}`))
	}
}

// K-008: the system node a worker's pooled HTTP/2 connection goes to goes silent. The next
// request must not hang: it fails over within the attempt deadline, and later ones start at the
// node that answered.
func TestK008ASilentSystemNodeIsFailedOver(t *testing.T) {
	short(t)
	var hitsA, hitsB atomic.Int32
	a, b := h2Server(t, whoami("a", &hitsA)), h2Server(t, whoami("b", &hitsB))
	p := newSilentProxy(t, a.Listener.Addr().String())
	c, err := NewTLSEndpoints([]string{p.url(), b.URL}, caOf(a), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var who WhoAmI
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "a" {
		t.Fatalf("before: %v %+v", err, who)
	}
	p.frozen.Store(true)
	start := time.Now()
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "b" {
		t.Fatalf("a silent node: %v %+v, want b's answer", err, who)
	}
	if d := time.Since(start); d > 10*AttemptTimeout {
		t.Fatalf("failing over took %v", d)
	}
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "b" || hitsA.Load() != 1 {
		t.Fatalf("the next request: %v %+v (a hit %d times)", err, who, hitsA.Load())
	}
}

// A server that accepts and never answers: a read fails over; a conditional write (PUT, whose
// resourceVersion makes a second send conflict rather than apply twice) fails over; any other
// write, which that node may have applied, is never sent twice: it fails as a timeout, and the
// next request starts at the next node. Nothing blocks past the deadline.
func TestK008AServerThatNeverAnswers(t *testing.T) {
	short(t)
	release := make(chan struct{})
	var hitsA, hitsB atomic.Int32
	a := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	b := h2Server(t, whoami("b", &hitsB))
	ctx := context.Background()
	mk := func() *Client {
		c, err := NewTLSEndpoints([]string{a.URL, b.URL}, caOf(a), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var who WhoAmI
	if err := mk().Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || who.Name != "b" {
		t.Fatalf("a read: %v %+v", err, who)
	}
	sl := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d", ResourceVersion: "7"}}
	if err := mk().UpdateStatus(ctx, sl); err != nil {
		t.Fatalf("a conditional write: %v", err)
	}
	c := mk()
	a0, b0 := hitsA.Load(), hitsB.Load()
	err := c.Call(ctx, http.MethodPost, "/apis/x/move", map[string]string{"to": "hv2"}, &who)
	if !IsTimeout(err) {
		t.Fatalf("a write to a node that never answers: %v, want a timeout", err)
	}
	if hitsA.Load() != a0+1 || hitsB.Load() != b0 {
		t.Fatalf("the write was sent %d times to a, %d to b", hitsA.Load()-a0, hitsB.Load()-b0)
	}
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || hitsA.Load() != a0+1 {
		t.Fatalf("after the timeout, the next request went to a again: %v", err)
	}
}

// A system node that answers but whose store has no quorum says so (503, HeaderUnavailable,
// before handling anything): every request, writes included, is sent to the next node, and
// later ones start there. An ordinary error answer is an answer: not sent elsewhere.
func TestK008ANodeWithoutQuorumIsToldApart(t *testing.T) {
	short(t)
	var hitsA, hitsB atomic.Int32
	a := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		hitsA.Add(1)
		if r.URL.Path == "/broken" {
			http.Error(w, `{"code":500,"reason":"InternalError","message":"x"}`, http.StatusInternalServerError)
			return
		}
		WriteUnavailable(w, "no quorum")
	})
	b := h2Server(t, whoami("b", &hitsB))
	c, err := NewTLSEndpoints([]string{a.URL, b.URL}, caOf(a), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var who WhoAmI
	if err := c.Call(ctx, http.MethodPost, "/auth/whoami", map[string]string{"a": "b"}, &who); err != nil || who.Name != "b" {
		t.Fatalf("a write to a node without quorum: %v %+v, want b's answer", err, who)
	}
	if err := c.Call(ctx, http.MethodGet, "/auth/whoami", nil, &who); err != nil || hitsA.Load() != 1 {
		t.Fatalf("the next request went to a again (%d): %v", hitsA.Load(), err)
	}
	// Every node without quorum: the 503 comes back, no spinning.
	c2, _ := NewTLSEndpoints([]string{a.URL, a.URL}, caOf(a), nil, nil)
	a0 := hitsA.Load()
	var e *Error
	if err := c2.Call(ctx, http.MethodGet, "/x", nil, nil); !errors.As(err, &e) || e.Code != http.StatusServiceUnavailable || !IsUnavailable(err) {
		t.Fatalf("every node without quorum: %v", err)
	}
	if hitsA.Load()-a0 != 2 {
		t.Fatalf("asked %d times, want once per endpoint", hitsA.Load()-a0)
	}
	// An ordinary error is an answer.
	c3, _ := NewTLSEndpoints([]string{a.URL, b.URL}, caOf(a), nil, nil)
	b0 := hitsB.Load()
	if err := c3.Call(ctx, http.MethodGet, "/broken", nil, nil); err == nil || hitsB.Load() != b0 {
		t.Fatalf("a 500 was sent on elsewhere: %v", err)
	}
}

// A watch on a connection whose peer goes silent ends (the HTTP/2 ping finds it dead), so the
// informer behind it lists again from another node instead of waiting forever.
func TestK008AWatchOnASilentConnectionEnds(t *testing.T) {
	short(t)
	a := h2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	p := newSilentProxy(t, a.Listener.Addr().String())
	c, err := NewTLSEndpoints([]string{p.url()}, caOf(a), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ch, err := c.Watch(ctx, "Silo", "", "")
	if err != nil {
		t.Fatal(err)
	}
	p.frozen.Store(true)
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("an event from a silent connection")
		}
	case <-ctx.Done():
		t.Fatal("the watch on a silent connection never ended")
	}
}
