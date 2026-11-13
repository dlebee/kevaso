package client

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Several control planes (design §3: any system node serves the API, no VIP or load balancer):
// a client given several API URLs sticks to the one that last answered and moves to the next when
// it can't be reached. A DNS name with one address per system node fails over the same way with
// no list at all: Go's dialer tries each address of a name in turn.

// SplitServers reads a server setting that may list several URLs, comma-separated (a kvo context's
// server, kevasod worker --server).
func SplitServers(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimRight(strings.TrimSpace(p), "/"); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NewTLSEndpoints is NewTLS for several control planes; it may learn more later (AddEndpoints).
func NewTLSEndpoints(servers []string, caPEM, certPEM, keyPEM []byte) (*Client, error) {
	if len(servers) == 0 {
		return nil, errors.New("no control-plane URL")
	}
	c, err := NewTLS(servers[0], caPEM, certPEM, keyPEM)
	if err != nil {
		return c, err
	}
	ft, err := newFailover(servers, c.HTTP.Transport.(*http.Transport))
	if err != nil {
		return nil, err
	}
	c.HTTP = &http.Client{Transport: ft}
	return c, nil
}

// Endpoints are the API URLs this client may use: one, or the failover list.
func (c *Client) Endpoints() []string {
	if f, ok := c.http().Transport.(*failover); ok {
		return f.urls()
	}
	return []string{c.BaseURL}
}

// AddEndpoints adds control planes this client may fail over to, after the ones it has (an agent
// learns them from the system nodes' Hosts: the one it was set up with may be the one lost). It
// says whether any was new. A client made for one server only (NewTLS) can't take more.
func (c *Client) AddEndpoints(servers ...string) bool {
	f, ok := c.http().Transport.(*failover)
	if !ok {
		return false
	}
	return f.add(servers)
}

// Pinned is a copy of c that talks to one control plane only (an agent's tunnel to each).
func (c *Client) Pinned(server string) *Client {
	p := &Client{BaseURL: strings.TrimRight(server, "/"), Token: c.Token, HTTP: c.HTTP}
	if f, ok := c.http().Transport.(*failover); ok {
		p.HTTP = &http.Client{Transport: f.base}
	}
	return p
}

// failover sends each request to the current endpoint, and to the next ones while a request
// couldn't reach any server at all (dial errors: nothing was sent). Requests that reached a server
// are never sent twice.
type failover struct {
	base  *http.Transport
	mu    sync.Mutex
	hosts []string // scheme://host:port of each endpoint
	cur   int
}

func newFailover(servers []string, base *http.Transport) (*failover, error) {
	f := &failover{base: base}
	for _, s := range servers {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("control-plane URL %q: want https://HOST:PORT", s)
		}
		f.hosts = append(f.hosts, u.Scheme+"://"+u.Host)
	}
	return f, nil
}

func (f *failover) add(servers []string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	added := false
	for _, s := range servers {
		u, err := url.Parse(strings.TrimRight(s, "/"))
		if err != nil || u.Host == "" {
			continue
		}
		h := u.Scheme + "://" + u.Host
		known := false
		for _, x := range f.hosts {
			known = known || x == h
		}
		if !known {
			f.hosts = append(f.hosts, h)
			added = true
		}
	}
	return added
}

func (f *failover) urls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hosts...)
}

// forUpgrade lets Upgrade clone the real transport (it needs HTTP/1.1 only) and keep failing over.
func (f *failover) forUpgrade(clone func(*http.Transport) *http.Transport) http.RoundTripper {
	return &failover{base: clone(f.base), hosts: f.urls(), cur: f.start()}
}

func (f *failover) start() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

func (f *failover) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	start, hosts := f.cur, append([]string(nil), f.hosts...)
	f.mu.Unlock()
	var last error
	for i := 0; i < len(hosts); i++ {
		n := (start + i) % len(hosts)
		u, _ := url.Parse(hosts[n])
		r := req.Clone(req.Context())
		r.URL.Scheme, r.URL.Host, r.Host = u.Scheme, u.Host, ""
		if i > 0 && req.Body != nil && req.Body != http.NoBody {
			if req.GetBody == nil {
				return nil, last
			}
			b, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = b
		}
		resp, err := f.base.RoundTrip(r)
		if err == nil {
			f.mu.Lock()
			f.cur = n
			f.mu.Unlock()
			return resp, nil
		}
		last = err
		if !unreached(err) || req.Context().Err() != nil {
			return nil, err
		}
	}
	return nil, last
}

// unreached: the request never got to a server (it couldn't connect), so another may take it.
func unreached(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	return false
}
