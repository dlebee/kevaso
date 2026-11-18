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
//   - a name is never followed to an address the outside can't reach from the internet (private,
//     the host's own: Special), unless a grant of the silo names that address itself (K-057,
//     K-092). The cluster's own ranges (silos, services, the mesh), loopback, link-local,
//     this-network, multicast and reserved are never opened, whatever a grant says. Every address
//     is checked when it is dialled, so a name that changes its answer (DNS rebinding) gets no
//     further;
//   - an address a grant allows by CIDR: passed through to where the client dialled, except an
//     address a grant never opens, or this host's own address unless the grant names that address;
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
	"syscall"
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
	// Approval: every request first needs a person's yes (design §8.7); Secret names it.
	Approval bool
	Secret   string
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
	// Ask, for an injection that needs a person's yes, waits until this request may have the
	// secret: nil once approved, an error when denied, expired or not possible.
	Ask func(ctx context.Context, siloKey, secret, host, method, path string) error
	// OrigDst is where the client meant to go (SO_ORIGINAL_DST after an nftables redirect).
	OrigDst func(net.Conn) (netip.AddrPort, error)
	// Dial reaches the outside; Resolve is used for names (default: the system's).
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Internal are addresses of this host and its cluster that a name must not lead to, on top of
	// the ranges Special always refuses (the host's own public addresses, the cluster's hosts and
	// load balancers): each is refused unless a grant names exactly it. Nil: none.
	Internal func() []netip.Prefix
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

func (g *Gate) dial(ctx context.Context, p Policy, addr string, byName bool) (net.Conn, error) {
	d := g.Dial
	if d == nil {
		var nd net.Dialer
		if byName {
			nd.Control = g.atConnect(p)
		}
		d = nd.DialContext
	}
	if !byName { // a CIDR rule's address, where the client dialled: still never a closed range or this host
		if err := g.cidrRefused(p, addr); err != nil { // a CIDR rule never opens a closed range or this host
			return nil, err
		}
		return d(ctx, "tcp", addr)
	}
	host, port, _ := net.SplitHostPort(addr)
	pn, _ := strconv.Atoi(port)
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
	// Every address the name resolves to is checked, and only one that passes is dialled.
	var refusals []string
	for _, ip := range ips {
		if err := g.refused(p, ip, uint16(pn)); err != nil {
			refusals = append(refusals, err.Error())
			continue
		}
		return d(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
	}
	return nil, fmt.Errorf("%s: %s", host, strings.Join(refusals, "; "))
}

// atConnect is the default dialer's last check, at connect time, on the socket's own address:
// whatever chose the address, it is checked again just before the connection is made.
func (g *Gate) atConnect(p Policy) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		a, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		return g.refused(p, a.Addr(), a.Port())
	}
}

// refused says why a name may not lead to a on port (nil: it may). The cluster's own ranges,
// loopback, link-local, this-network, multicast and reserved are never opened, whatever a grant
// says. Any other address Special refuses, or one in Internal, is opened only by a CIDR rule of
// the silo's grants that names it: inside the refused range, for that port, over TCP (a wider
// rule, 0.0.0.0/0, doesn't name it).
func (g *Gate) refused(p Policy, resolved netip.Addr, port uint16) error {
	a := resolved.Unmap().WithZone("") // a zone would make every range miss it
	if _, why := neverOpened(a); why != "" {
		return fmt.Errorf("it resolves to %s (%s), which a grant never opens", resolved, why)
	}
	r, why := Special(a)
	if why == "" && g.Internal != nil {
		for _, pr := range g.Internal() {
			if pr.Contains(a) && (!r.IsValid() || pr.Bits() > r.Bits()) {
				r, why = pr, "an address of this host or its cluster"
			}
		}
	}
	if why == "" {
		return nil
	}
	if namedByCIDR(p, a, port, r) {
		return nil
	}
	return fmt.Errorf("it resolves to %s (%s), which a name never leads to: name the address itself in a grant's egress `to` (as %s) to allow it", resolved, why, netip.PrefixFrom(a, a.BitLen()))
}

// cidrRefused says why a CIDR rule may not dial addr (nil: it may). The same ranges a name never
// opens are refused here too, before the dial. This host's own addresses, the ones Internal
// lists, are refused unless a CIDR rule names that address itself: a wide rule does not.
func (g *Gate) cidrRefused(p Policy, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return err
	}
	a := ap.Addr().Unmap().WithZone("")
	if _, closed := neverOpened(a); closed != "" {
		return fmt.Errorf("%s is %s, which a grant never opens", a, closed)
	}
	if g.Internal == nil {
		return nil
	}
	var own netip.Prefix
	why := ""
	for _, pr := range g.Internal() {
		if pr.Contains(a) && (!own.IsValid() || pr.Bits() > own.Bits()) {
			own, why = pr, "an address of this host or its cluster"
		}
	}
	if why == "" || namedByCIDR(p, a, ap.Port(), own) {
		return nil
	}
	return fmt.Errorf("%s is %s, which a grant never opens", a, why)
}

// namedByCIDR reports whether a CIDR rule of p names a itself: the rule is inside r, covers a,
// and allows port over TCP. A wider rule (0.0.0.0/0) does not name it.
func namedByCIDR(p Policy, a netip.Addr, port uint16, r netip.Prefix) bool {
	for _, c := range p.CIDRs {
		if c.Prefix.Contains(a) && c.Prefix.Bits() >= r.Bits() && r.Contains(c.Prefix.Addr()) &&
			c.AllowsPort(int(port)) && contains(c.Protocols, "tcp") {
			return true
		}
	}
	return false
}

// special are the ranges a host name never leads to: the host itself, its networks and the
// cluster's (all of 10/8: the mesh, silos and services are in it), and nothing the internet can
// route to. IPv6 forms that carry an IPv4 address are checked on that address.
var special = []struct {
	p   netip.Prefix
	why string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "this network"},
	{netip.MustParsePrefix("10.0.0.0/8"), "a private address: the mesh, silos and services are in it"},
	{netip.MustParsePrefix("100.64.0.0/10"), "a shared address (carrier-grade NAT)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback: this host itself"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local: a cloud's metadata, the silos' local endpoint"},
	{netip.MustParsePrefix("172.16.0.0/12"), "a private address"},
	{netip.MustParsePrefix("192.0.0.0/24"), "an IETF protocol address"},
	{netip.MustParsePrefix("192.168.0.0/16"), "a private address"},
	{netip.MustParsePrefix("198.18.0.0/15"), "a benchmarking address"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
	{netip.MustParsePrefix("::/96"), "unspecified, loopback or IPv4-compatible"},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "local NAT64"},
	{netip.MustParsePrefix("100::/64"), "discard"},
	{netip.MustParsePrefix("fc00::/7"), "a unique local address"},
	{netip.MustParsePrefix("fe80::/10"), "link-local"},
	{netip.MustParsePrefix("fec0::/10"), "site-local"},
	{netip.MustParsePrefix("ff00::/8"), "multicast"},
}

// carriedIPv4 is the IPv4 address inside a NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address.
func carriedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case netip.MustParsePrefix("64:ff9b::/96").Contains(a): // the IPv4 address in its last 32 bits
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case netip.MustParsePrefix("2002::/16").Contains(a): // the IPv4 address after 2002:
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	default:
		return netip.Addr{}, false
	}
}

// neverOpened reports the range a grant never opens when a is inside one: the cluster's own
// ranges, loopback, link-local, this-network, multicast or reserved, including an IPv4 address
// carried in NAT64 or 6to4. why is "" when a grant may still name it (an ordinary private
// address, the host's own public address).
func neverOpened(a netip.Addr) (netip.Prefix, string) {
	a = a.Unmap().WithZone("")
	if v4, ok := carriedIPv4(a); ok {
		if _, why := v1.ClosedRange(netip.PrefixFrom(v4, v4.BitLen())); why != "" {
			return netip.PrefixFrom(a, a.BitLen()), why + " (as " + v4.String() + ")"
		}
	}
	return v1.ClosedRange(netip.PrefixFrom(a, a.BitLen()))
}

// Special says whether a host name may never lead to a, and why: the smallest range of the
// refused ones holding it, else "" (an ordinary internet address). Pure.
func Special(a netip.Addr) (netip.Prefix, string) {
	a = a.Unmap().WithZone("")
	if v4, ok := carriedIPv4(a); ok {
		if _, why := Special(v4); why != "" {
			return netip.PrefixFrom(a, 128), why + " (as " + v4.String() + ")"
		}
	}
	best, why := netip.Prefix{}, ""
	for _, s := range special {
		if s.p.Contains(a) && (!best.IsValid() || s.p.Bits() > best.Bits()) {
			best, why = s.p, s.why
		}
	}
	if why == "" && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return netip.PrefixFrom(a, 32), "broadcast"
	}
	return best, why
}

// pass splices the client to addr, replaying the ClientHello already read.
func (g *Gate) pass(ctx context.Context, c net.Conn, hello []byte, p Policy, addr string, byName bool) {
	up, err := g.dial(ctx, p, addr, byName)
	if err != nil {
		g.log("gate: BLOCKED %s → %s: %v", p.Key, addr, err)
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
	inj, failed := g.Injections(ctx, p.Key)
	if failed != nil {
		// Said to the silo too (K-076): TLS is ended as for any injection, and every request is
		// answered with why there is no secret, instead of a connection closed with nothing said.
		g.log("gate: BLOCKED %s → %s: the secret can't be injected: %v", p.Key, sni, failed)
	}
	in, ok := inj[sni]
	if failed == nil && !ok { // the grant names it, but the secret isn't there (no value yet, or not allowed)
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
		DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return g.dial(ctx, p, addr, true) },
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
		// The silo is told why (a target refused, the host unreachable), never a bare 502.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.log("gate: BLOCKED %s %s %s%s: %v", p.Key, r.Method, sni, r.URL.Path, err)
			http.Error(w, "egress gate: "+err.Error(), http.StatusBadGateway)
		},
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
		if failed != nil {
			http.Error(w, "egress gate: the secret for "+sni+" can't be injected: "+failed.Error(), http.StatusServiceUnavailable)
			return
		}
		if in.Approval {
			var err error
			if g.Ask == nil {
				err = errors.New("this gate can't ask for approvals")
			} else {
				err = g.Ask(r.Context(), p.Key, in.Secret, sni, r.Method, r.URL.Path)
			}
			if err != nil {
				g.log("gate: BLOCKED %s %s %s%s: %v", p.Key, r.Method, sni, r.URL.Path, err)
				http.Error(w, "egress needs a person's yes: "+err.Error(), http.StatusForbidden)
				return
			}
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
