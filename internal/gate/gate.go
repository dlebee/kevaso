// Package gate is the egress gate on a worker (design §8.1 tier 2, research E025): a silo's
// outbound TLS to the ports its grants name by host is redirected here (nftables), and the gate
// decides by the name the client asks for (SNI), never by the address it dialled:
//
//   - a host a grant injects a secret for: TLS is ended with the host's egress CA (which the silo
//     trusts), every request must be for that same host, the silo's own header is replaced by the
//     secret, and the gate dials the real host itself, verifying its certificate. The secret never
//     enters the silo;
//   - a host a grant allows by name: the TLS stream is passed through untouched, to the name the
//     client asked for (resolved here, so an address can't be smuggled in);
//   - an address a grant allows by CIDR: passed through to where the client dialled;
//   - anything else, including no SNI: refused.
//
// The gate knows which silo is calling from the source address: the bridge drops any packet a
// silo sends with an address that isn't its own.
package gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// Policy is what one silo may reach through the gate.
type Policy struct {
	Key    string            // namespace/name, for logs
	Names  []v1.ParsedEgress // host-name rules
	CIDRs  []v1.ParsedEgress // CIDR rules (passthrough when the redirect caught them too)
	Inject map[string]bool   // hosts a secret is injected for (port 443)
}

// Injection is a header to set for a host.
type Injection struct {
	Header, Value string
}

// PolicyFor builds a silo's gate policy from its grants. Pure.
func PolicyFor(s *v1.Silo, grants []*v1.Grant) Policy {
	p := Policy{Key: s.Namespace + "/" + s.Name, Inject: map[string]bool{}}
	for _, g := range v1.GrantsFor(s, grants) {
		for _, r := range g.Spec.Egress {
			e, err := r.Parse()
			if err != nil {
				continue
			}
			if e.Host != "" {
				p.Names = append(p.Names, e)
			} else {
				p.CIDRs = append(p.CIDRs, e)
			}
		}
		for _, sec := range g.Spec.Secrets {
			if sec.Delivery() == v1.DeliverInject && sec.To != nil {
				p.Inject[strings.ToLower(sec.To.Host)] = true
			}
		}
	}
	return p
}

// Ports are the TCP ports the host redirects to the gate for this silo (none: no redirect).
func (p Policy) Ports() []v1.PortRange {
	var out []v1.PortRange
	seen := map[v1.PortRange]bool{}
	add := func(r v1.PortRange) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	if len(p.Inject) > 0 {
		add(v1.PortRange{From: 443, To: 443})
	}
	for _, n := range p.Names {
		for _, r := range n.Ports {
			add(r)
		}
	}
	return out
}

// Decision is what the gate does with one connection.
type Decision int

const (
	Refuse      Decision = iota
	Inject               // end TLS, add the secret, proxy
	PassName             // pass through to the SNI name
	PassAddress          // pass through to the original destination
)

// Decide is the gate's rule for one connection. Pure.
func (p Policy) Decide(sni string, dst netip.AddrPort) Decision {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if sni != "" {
		if dst.Port() == 443 && p.Inject[sni] {
			return Inject
		}
		for _, n := range p.Names {
			if v1.MatchHost(n.Host, sni) && n.AllowsPort(int(dst.Port())) {
				return PassName
			}
		}
	}
	for _, c := range p.CIDRs {
		if c.Prefix.Contains(dst.Addr()) && c.AllowsPort(int(dst.Port())) && contains(c.Protocols, "tcp") {
			return PassAddress
		}
	}
	return Refuse
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Gate serves redirected connections.
type Gate struct {
	CA *CA
	// Silo finds the policy of the local silo with this address (false: not one of ours).
	Silo func(ip netip.Addr) (Policy, bool)
	// Injections gives the headers to add for a silo, by host (fetched from the control plane).
	Injections func(ctx context.Context, siloKey string) (map[string]Injection, error)
	// OrigDst is where the client meant to go (SO_ORIGINAL_DST after an nftables redirect).
	OrigDst func(net.Conn) (netip.AddrPort, error)
	// Dial reaches the outside; Resolve is used for names (default: the system's).
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Upstream verifies the real hosts (nil: the system roots).
	Upstream *x509.CertPool
	Log      func(string, ...any)
}

func (g *Gate) log(f string, a ...any) {
	if g.Log != nil {
		g.Log(f, a...)
	}
}

// Serve accepts redirected connections until l closes.
func (g *Gate) Serve(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go g.handle(ctx, c)
	}
}

func (g *Gate) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	src, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	p, ok := g.Silo(src.Addr().Unmap())
	if !ok {
		g.log("gate: BLOCKED %s: not a silo on this host", src)
		return
	}
	dst, err := g.OrigDst(c)
	if err != nil {
		g.log("gate: %s: original destination: %v", p.Key, err)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	hello, sni, err := peekClientHello(c)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		sni = "" // not TLS: only a CIDR rule can let it through
	}
	switch p.Decide(sni, dst) {
	case Inject:
		g.inject(ctx, c, hello, p, sni, dst)
	case PassName:
		g.pass(ctx, c, hello, p, net.JoinHostPort(sni, strconv.Itoa(int(dst.Port()))), true)
	case PassAddress:
		g.pass(ctx, c, hello, p, dst.String(), false)
	default:
		g.log("gate: BLOCKED %s → %s sni=%q (no grant)", p.Key, dst, sni)
	}
}

func (g *Gate) dial(ctx context.Context, addr string, byName bool) (net.Conn, error) {
	d := g.Dial
	if d == nil {
		var nd net.Dialer
		d = nd.DialContext
	}
	if !byName {
		return d(ctx, "tcp", addr)
	}
	host, port, _ := net.SplitHostPort(addr)
	resolve := g.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: %v", host, err)
	}
	return d(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
}

// pass splices the client to addr, replaying the ClientHello already read.
func (g *Gate) pass(ctx context.Context, c net.Conn, hello []byte, p Policy, addr string, byName bool) {
	up, err := g.dial(ctx, addr, byName)
	if err != nil {
		g.log("gate: %s → %s: %v", p.Key, addr, err)
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(hello); err != nil {
		return
	}
	g.log("gate: ALLOWED %s → %s (passthrough)", p.Key, addr)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); closeWrite(c); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// inject ends TLS for sni and proxies each request to the real host with the secret added.
func (g *Gate) inject(ctx context.Context, c net.Conn, hello []byte, p Policy, sni string, dst netip.AddrPort) {
	inj, err := g.Injections(ctx, p.Key)
	if err != nil {
		g.log("gate: %s: injections: %v", p.Key, err)
		return
	}
	in, ok := inj[sni]
	if !ok { // the grant names it, but the secret isn't there (no value yet, or not allowed)
		g.log("gate: BLOCKED %s → %s: no secret to inject", p.Key, sni)
		return
	}
	leaf, err := g.CA.Leaf(sni)
	if err != nil {
		g.log("gate: %s: leaf for %s: %v", p.Key, sni, err)
		return
	}
	tc := tls.Server(&replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(hello), c)}, &tls.Config{
		// HTTP/1.1 towards the silo (the gate serves this one connection itself); upstream may use h2.
		Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		g.log("gate: %s: handshake: %v", p.Key, err)
		return
	}
	target := sni
	if dst.Port() != 443 {
		target = net.JoinHostPort(sni, strconv.Itoa(int(dst.Port())))
	}
	transport := &http.Transport{
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return g.dial(ctx, addr, true) },
		TLSClientConfig:   &tls.Config{RootCAs: g.Upstream, MinVersion: tls.VersionTLS12, ServerName: sni},
		ForceAttemptHTTP2: true,
	}
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "https", target, sni
			r.Out.Header.Del(in.Header) // the silo's own never goes out
			r.Out.Header.Set(in.Header, in.Value)
		},
		Transport: transport,
		ErrorLog:  nil,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != sni { // domain fronting: the request is for another host than the TLS name
			g.log("gate: BLOCKED %s: Host %q over TLS for %q", p.Key, r.Host, sni)
			http.Error(w, "egress not allowed", http.StatusForbidden)
			return
		}
		g.log("gate: ALLOWED %s %s %s%s (%s injected)", p.Key, r.Method, sni, r.URL.Path, in.Header)
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 30 * time.Second}
	_ = srv.Serve(newOneConn(tc)) // returns once the silo closes the connection
}

// ── reading the ClientHello without answering it ─────────────────────────────

var errHelloRead = errors.New("client hello read")

// recordConn records what's read and refuses writes, so a tls.Server can parse a ClientHello
// without the client seeing anything.
type recordConn struct {
	net.Conn
	r   io.Reader
	buf bytes.Buffer
}

func (r *recordConn) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

func (r *recordConn) Write([]byte) (int, error) { return 0, errHelloRead }

// peekClientHello reads the client's first TLS record(s) and returns them and the SNI.
func peekClientHello(c net.Conn) ([]byte, string, error) {
	rc := &recordConn{Conn: c, r: bufio.NewReader(c)}
	var sni string
	err := tls.Server(rc, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, errHelloRead
	}}).Handshake()
	if sni == "" && !errors.Is(err, errHelloRead) {
		return rc.buf.Bytes(), "", err
	}
	return rc.buf.Bytes(), sni, nil
}

// replayConn reads from r (the recorded hello, then the connection).
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ── one connection as a listener ─────────────────────────────────────────────

type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
}

func newOneConn(c net.Conn) *oneConn {
	return &oneConn{c: &closeNotify{Conn: c}, done: make(chan struct{})}
}

type closeNotify struct {
	net.Conn
	once sync.Once
	l    *oneConn
}

func (o *oneConn) Accept() (net.Conn, error) {
	var c net.Conn
	o.once.Do(func() {
		cn := o.c.(*closeNotify)
		cn.l = o
		c = cn
	})
	if c != nil {
		return c, nil
	}
	<-o.done
	return nil, net.ErrClosed
}

func (c *closeNotify) Close() error {
	c.once.Do(func() { close(c.l.done) })
	return c.Conn.Close()
}

func (o *oneConn) Close() error   { return nil }
func (o *oneConn) Addr() net.Addr { return o.c.LocalAddr() }
