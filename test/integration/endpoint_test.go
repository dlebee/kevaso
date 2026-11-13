package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// endpoints is one host's local endpoint (ADR 0009) as its silos reach it. On a real host a
// silo's source address on the bridge says who asks; here each silo gets a loopback listener of
// its own and the listener a request arrived on says who asks: the arrival point, never the
// request. Silos call it with a plain HTTP client, as curl in a silo would.
type endpoints struct {
	ep     *agent.Endpoint
	mu     sync.Mutex
	byPort map[int]kri.ID
	urls   map[string]string // by silo uid
}

func (c *cluster) endpoints(t *testing.T, host string) *endpoints {
	t.Helper()
	return newEndpoints(t, c.host(t, host), host)
}

func newEndpoints(t *testing.T, hc *client.Client, host string) *endpoints {
	e := &endpoints{byPort: map[int]kri.ID{}, urls: map[string]string{}}
	e.ep = &agent.Endpoint{Client: hc, HostName: host, Identify: func(r *http.Request) (kri.ID, bool) {
		la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if !ok {
			return kri.ID{}, false
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		id, ok := e.byPort[la.(*net.TCPAddr).Port]
		return id, ok
	}}
	return e
}

// add gives silo s its own way in.
func (e *endpoints) add(t *testing.T, s *v1.Silo) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := e.ep.Server()
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	port := l.Addr().(*net.TCPAddr).Port
	e.mu.Lock()
	e.byPort[port] = kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID}
	e.urls[s.UID] = "http://127.0.0.1:" + strconv.Itoa(port)
	e.mu.Unlock()
}

// epAnswer is what the endpoint said.
type epAnswer struct {
	code   int
	body   string
	header http.Header
}

// msg is an error answer's message.
func (a epAnswer) msg() string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(a.body), &e)
	return e.Error
}

func (a epAnswer) pending() string { return a.header.Get("Kevaso-Approval") }

// call is one request from silo s: what `curl -H 'Kevaso-Local: 1' http://169.254.42.1PATH` sends.
func (e *endpoints) call(t *testing.T, s *v1.Silo, method, path string, body []byte) epAnswer {
	t.Helper()
	e.mu.Lock()
	base := e.urls[s.UID]
	e.mu.Unlock()
	req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = v1.EndpointAddress
	req.Header.Set(v1.EndpointHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return epAnswer{resp.StatusCode, string(b), resp.Header}
}

// ask is call, waiting for a person's yes as a silo would: on 428 it asks again every interval
// with approval=NAME, until something else comes back. waiting hears the approval's name once.
func (e *endpoints) ask(t *testing.T, ctx context.Context, s *v1.Silo, method, path string, body []byte, every time.Duration, waiting func(string)) epAnswer {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	told, poll := "", ""
	for {
		a := e.call(t, s, method, path+poll, body)
		if a.code != http.StatusPreconditionRequired {
			return a
		}
		if name := a.pending(); name != told {
			told = name
			if waiting != nil {
				waiting(name)
			}
		}
		poll = sep + "approval=" + told
		select {
		case <-ctx.Done():
			return epAnswer{code: -1, body: `{"error":"stopped waiting"}`}
		case <-time.After(every):
		}
	}
}
