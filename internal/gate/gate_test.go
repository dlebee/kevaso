package gate

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestPolicy(t *testing.T) {
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1"}, Spec: v1.SiloSpec{Grants: []string{"anthropic", "github", "p2p"}}}
	grants := []*v1.Grant{
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "anthropic"}, Spec: v1.GrantSpec{Secrets: []v1.GrantSecret{
			{Name: "anthropic-key", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "API.anthropic.com", Header: "x-api-key", Format: "{{value}}"}}}}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "github"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "*.github.com"}, {To: "github.com", Ports: []string{"443", "22"}}}}},
		{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "p2p"}, Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "198.51.100.0/24", Ports: []string{"443"}}}}},
	}
	p := PolicyFor(s, grants)
	ap := netip.MustParseAddrPort
	for _, c := range []struct {
		sni  string
		dst  string
		want Decision
	}{
		{"api.anthropic.com", "203.0.113.9:443", Inject},
		{"API.Anthropic.com.", "203.0.113.9:443", Inject},
		{"api.anthropic.com", "203.0.113.9:8443", Refuse}, // injection is for 443
		{"api.github.com", "203.0.113.9:443", PassName},
		{"github.com", "203.0.113.9:22", PassName},
		{"gist.github.com", "203.0.113.9:22", Refuse}, // *.github.com is 443 only
		{"evil.com", "203.0.113.9:443", Refuse},
		{"", "203.0.113.9:443", Refuse},               // no SNI
		{"evil.com", "198.51.100.7:443", PassAddress}, // the CIDR grant
		{"", "198.51.100.7:443", PassAddress},
		{"", "198.51.100.7:80", Refuse},
	} {
		if got := p.Decide(c.sni, ap(c.dst)); got != c.want {
			t.Errorf("Decide(%q, %s) = %v, want %v", c.sni, c.dst, got, c.want)
		}
	}
	got := fmt.Sprint(p.Ports())
	if got != "[443 22]" {
		t.Errorf("redirected ports %s", got)
	}
	if len(PolicyFor(&v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "x"}}, grants).Ports()) != 0 {
		t.Error("a silo without grants gets a redirect")
	}
}

// The upstream "internet": answers for any name with a certificate from its own CA, and echoes
// what it got (the Authorization value only as a prefix, like E025's echo server).
type upstream struct {
	addr  string
	roots *x509.CertPool
	ca    *CA
	mu    sync.Mutex
	seen  []map[string]string
}

func newUpstream(t *testing.T) *upstream {
	ca, err := LoadOrCreateCA(t.TempDir(), "internet")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstream{ca: ca, roots: x509.NewCertPool()}
	u.roots.AppendCertsFromPEM(ca.PEM)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := map[string]string{"host": r.Host, "auth": r.Header.Get("Authorization"), "path": r.URL.Path}
		u.mu.Lock()
		u.seen = append(u.seen, got)
		u.mu.Unlock()
		_ = json.NewEncoder(w).Encode(got)
	}))
	srv.TLS = &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := ca.Leaf(h.ServerName)
		return &c, err
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u.addr = srv.Listener.Addr().String()
	return u
}

type env struct {
	gate   string // the gate's listener
	silo   *x509.CertPool
	dst    netip.AddrPort
	up     *upstream
	dstMu  sync.Mutex
	logged []string
}

func setup(t *testing.T, cidrPort string) *env {
	up := newUpstream(t)
	ca, err := LoadOrCreateCA(t.TempDir(), "hv1")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{up: up, silo: x509.NewCertPool(), dst: netip.MustParseAddrPort("203.0.113.9:443")}
	e.silo.AppendCertsFromPEM(ca.PEM)
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1"}, Spec: v1.SiloSpec{Grants: []string{"g"}}}
	g := &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "g"}, Spec: v1.GrantSpec{
		Egress:  []v1.EgressRule{{To: "pass.test"}, {To: "127.0.0.0/8", Ports: []string{cidrPort}}},
		Secrets: []v1.GrantSecret{{Name: "key", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "api.allowed.test"}}},
	}}
	pol := PolicyFor(s, []*v1.Grant{g})
	_, upPort, _ := net.SplitHostPort(up.addr)
	gt := &Gate{
		CA: ca,
		Silo: func(ip netip.Addr) (Policy, bool) {
			return pol, ip.IsLoopback()
		},
		Injections: func(context.Context, string) (map[string]Injection, error) {
			return map[string]Injection{"api.allowed.test": {Header: "Authorization", Value: "Bearer sk-test-123"}}, nil
		},
		OrigDst: func(net.Conn) (netip.AddrPort, error) {
			e.dstMu.Lock()
			defer e.dstMu.Unlock()
			return e.dst, nil
		},
		// Every name is the upstream; the "internet" port 443 is its port.
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(addr)
			if port == "443" {
				port = upPort
			}
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		Upstream: up.roots,
		Log: func(f string, a ...any) {
			e.dstMu.Lock()
			e.logged = append(e.logged, fmt.Sprintf(f, a...))
			e.dstMu.Unlock()
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = gt.Serve(context.Background(), l) }()
	e.gate = l.Addr().String()
	return e
}

func (e *env) setDst(s string) {
	e.dstMu.Lock()
	e.dst = netip.MustParseAddrPort(s)
	e.dstMu.Unlock()
}

// get is the silo: HTTPS to the gate as if to sni, trusting roots, with an optional Host and
// Authorization of its own.
func (e *env) get(sni string, roots *x509.CertPool, host, auth string) (map[string]string, int, error) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", e.gate)
		},
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: sni},
	}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://"+sni+"/v1/models", nil)
	if host != "" {
		req.Host = host
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var got map[string]string
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &got)
	return got, resp.StatusCode, nil
}

// E025's cases, in one process.
func TestGate(t *testing.T) {
	e := setup(t, "9")

	// 1. The allowed host gets the injected key; the silo sent none and holds none.
	got, code, err := e.get("api.allowed.test", e.silo, "", "")
	if err != nil || code != 200 || got["auth"] != "Bearer sk-test-123" || got["host"] != "api.allowed.test" {
		t.Fatalf("inject: %v %d %v", got, code, err)
	}
	// 2. A header the silo sends is replaced, not forwarded.
	got, _, err = e.get("api.allowed.test", e.silo, "", "Bearer stolen-or-fake")
	if err != nil || got["auth"] != "Bearer sk-test-123" {
		t.Fatalf("replace: %v %v", got, err)
	}
	// 3. A host no grant names: the handshake is refused, even ignoring certificates.
	if _, _, err := e.get("other.blocked.test", e.silo, "", ""); err == nil {
		t.Fatal("blocked host answered")
	}
	insecure := &tls.Config{InsecureSkipVerify: true, ServerName: "other.blocked.test"} //nolint:gosec // the point of the test
	if c, err := tls.Dial("tcp", e.gate, insecure); err == nil {
		_ = c.Close()
		t.Fatal("blocked host handshake succeeded with -k")
	}
	// 4. No SNI at all.
	if c, err := tls.Dial("tcp", e.gate, &tls.Config{InsecureSkipVerify: true}); err == nil { //nolint:gosec // the point of the test
		_ = c.Close()
		t.Fatal("TLS without SNI succeeded")
	}
	// 5. Domain fronting: the allowed name in TLS, another Host in the request.
	if _, code, err := e.get("api.allowed.test", e.silo, "other.blocked.test", ""); err != nil || code != http.StatusForbidden {
		t.Fatalf("domain fronting: %d %v", code, err)
	}
	// 6. A name allowed without a secret passes through untouched: the silo sees the real
	// certificate (not the egress CA's) and nothing is injected.
	got, code, err = e.get("pass.test", e.up.roots, "", "")
	if err != nil || code != 200 || got["auth"] != "" || got["host"] != "pass.test" {
		t.Fatalf("passthrough by name: %v %d %v", got, code, err)
	}
	if _, _, err := e.get("pass.test", e.silo, "", ""); err == nil {
		t.Fatal("passthrough was ended by the egress CA")
	}
	// 7. An address allowed by CIDR: any bytes pass to where the silo dialled.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	e.setDst("127.0.0.1:" + port) // what the silo dialled
	// The CIDR grant is for port 9 only: this port is refused.
	if c, err := net.Dial("tcp", e.gate); err == nil {
		_, _ = c.Write([]byte("hello\n"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if line, err := bufio.NewReader(c).ReadString('\n'); err == nil {
			t.Fatalf("CIDR grant for port 9 let port %s through: %q", port, line)
		}
		_ = c.Close()
	}

	e.dstMu.Lock()
	log := strings.Join(e.logged, "\n")
	e.dstMu.Unlock()
	for _, want := range []string{"ALLOWED dev/claude-1 GET api.allowed.test/v1/models (Authorization injected)", `BLOCKED dev/claude-1 → 203.0.113.9:443 sni="other.blocked.test"`, `sni=""`, "Host \"other.blocked.test\" over TLS"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "sk-test-123") {
		t.Fatal("the secret is in the gate's log")
	}
}

// A CIDR grant passes raw TCP to the original destination.
func TestGateCIDRPassthrough(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	e := setup(t, port)
	defer func() { _ = echo.Close() }()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			_, _ = io.Copy(c, c)
			_ = c.Close()
		}
	}()
	e.setDst("127.0.0.1:" + port)
	c, err := net.Dial("tcp", e.gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("hello\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello\n" {
		t.Fatalf("CIDR passthrough: %q %v", line, err)
	}
}
