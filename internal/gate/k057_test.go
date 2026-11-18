package gate

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// K-057, K-092: egress by host name. The gate resolves a granted name itself and dials what it
// resolves to, from the host. A name whose owner points it at a private address, or at the host's
// own, would reach that address from the host, past the bridge's input drop and other silos'
// allowFrom. Such an address is refused unless a grant of the silo names it (a CIDR rule inside
// that range), for every address a name resolves to, at every connection (a name that changes its
// answer, DNS rebinding, gets no more than its first), IPv4 and IPv6 alike. The cluster's own
// ranges, loopback and link-local are never opened even when the grant names them (K-124).

// nameRig is a gate for one silo with grants g, whose resolver answers what answers says (one
// list per call, the last repeated), and whose dialer records every address it is asked for and
// reaches the test's upstream for all of them.
type nameRig struct {
	gate    string
	silo    *x509.CertPool
	up      *upstream
	mu      sync.Mutex
	answers [][]netip.Addr
	dialled []string
	logged  []string
}

func newNameRig(t *testing.T, own []netip.Prefix, egress ...v1.EgressRule) *nameRig {
	t.Helper()
	up := newUpstream(t)
	ca, err := LoadOrCreateCA(t.TempDir(), "hv1")
	if err != nil {
		t.Fatal(err)
	}
	r := &nameRig{up: up, silo: x509.NewCertPool()}
	r.silo.AppendCertsFromPEM(ca.PEM)
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1"}, Spec: v1.SiloSpec{Grants: []string{"g"}}}
	g := &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "g"}, Spec: v1.GrantSpec{
		Egress:  append([]v1.EgressRule{{To: "pass.test"}}, egress...),
		Secrets: []v1.GrantSecret{{Name: "key", Deliver: v1.DeliverInject, To: &v1.InjectTarget{Host: "api.allowed.test"}}},
	}}
	pol := PolicyFor(s, []*v1.Grant{g})
	gt := &Gate{
		CA:       ca,
		Silo:     func(ip netip.Addr) (Policy, bool) { return pol, ip.IsLoopback() },
		Internal: func() []netip.Prefix { return own },
		Injections: func(context.Context, string) (map[string]Injection, error) {
			return map[string]Injection{"api.allowed.test": {Header: "Authorization", Value: "Bearer sk-test-123", Secret: "key"}}, nil
		},
		OrigDst: func(net.Conn) (netip.AddrPort, error) { return netip.MustParseAddrPort("203.0.113.9:443"), nil },
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			a := r.answers[0]
			if len(r.answers) > 1 {
				r.answers = r.answers[1:]
			}
			return a, nil
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			r.mu.Lock()
			r.dialled = append(r.dialled, host)
			r.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, network, up.addr)
		},
		Upstream: up.roots,
		Log: func(f string, a ...any) {
			r.mu.Lock()
			r.logged = append(r.logged, fmt.Sprintf(f, a...))
			r.mu.Unlock()
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() { _ = gt.Serve(context.Background(), l) }()
	r.gate = l.Addr().String()
	return r
}

func (r *nameRig) answer(lists ...[]netip.Addr) {
	r.mu.Lock()
	r.answers, r.dialled, r.logged = lists, nil, nil
	r.mu.Unlock()
}

func (r *nameRig) seen() ([]string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.dialled), strings.Join(r.logged, "\n")
}

// passes: TLS through the gate to the passthrough name, with the upstream's certificate.
func (r *nameRig) passes() bool {
	e := &env{gate: r.gate}
	_, code, err := e.get("pass.test", r.up.roots, "", "")
	return err == nil && code == 200
}

// injects: a request through the gate's injection, as the silo makes it.
func (r *nameRig) injects() (int, error) {
	e := &env{gate: r.gate}
	_, code, err := e.get("api.allowed.test", r.silo, "", "")
	return code, err
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// Every kind of address a name must not lead to from the host, IPv4 and IPv6.
var refusedTargets = []string{
	"127.0.0.1", "127.8.9.10", "0.0.0.0", "0.1.2.3", // loopback, this network
	"10.0.0.5", "10.63.0.2", "10.62.0.1", "10.64.0.7", "10.65.0.10", // private: the mesh, silos, services
	"172.16.0.1", "172.31.255.254", "192.168.1.1", // private
	"100.64.0.1", "100.127.255.254", // shared (carrier-grade NAT)
	"169.254.169.254", "169.254.42.1", // link-local: a cloud's metadata, the local endpoint
	"192.0.0.8", "198.18.0.1", // IETF protocol assignments, benchmarking
	"224.0.0.1", "239.1.2.3", "240.0.0.1", "255.255.255.255", // multicast, reserved, broadcast
	"::1", "::", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1", // IPv6 loopback, link- and site-local, ULA, multicast
	"::ffff:127.0.0.1", "::ffff:10.0.0.5", "::ffff:169.254.169.254", // IPv4-mapped
	"64:ff9b::7f00:1", "64:ff9b::a00:5", "2002:7f00:1::1", "2002:a9fe:a9fe::1", // NAT64 and 6to4 of a refused one
	"::127.0.0.1", "64:ff9b:1::1", "100::1", // IPv4-compatible, local NAT64, discard
}

func TestAGrantedNameNeverLeadsToAPrivateAddress(t *testing.T) {
	r := newNameRig(t, nil)
	r.answer(addrs("203.0.113.9"))
	if !r.passes() {
		t.Fatal("a public address was refused")
	}
	if code, err := r.injects(); err != nil || code != 200 {
		t.Fatalf("a public address was refused for an injection: %d %v", code, err)
	}
	for _, target := range refusedTargets {
		r.answer(addrs(target))
		if r.passes() {
			t.Errorf("pass.test resolving to %s was passed through", target)
		}
		code, err := r.injects()
		if err == nil && code == 200 {
			t.Errorf("api.allowed.test resolving to %s got its secret injected", target)
		}
		dialled, log := r.seen()
		if len(dialled) > 0 {
			t.Errorf("%s: the gate dialled %v", target, dialled)
		}
		phrase := "egress `to`"
		if _, why := neverOpened(netip.MustParseAddr(target)); why != "" {
			phrase = "which a grant never opens" // cluster, loopback, link-local: naming it does not open it
		}
		if !strings.Contains(log, netip.MustParseAddr(target).String()) || !strings.Contains(log, phrase) {
			t.Errorf("%s: the refusal doesn't name the address and what to do:\n%s", target, log)
		}
	}
}

// The silo gets the reason for a refused injection, not a bare error.
func TestARefusedTargetIsExplainedToTheSilo(t *testing.T) {
	r := newNameRig(t, nil)
	r.answer(addrs("127.0.0.1"))
	code, err := r.injects()
	if err != nil || code != http.StatusBadGateway {
		t.Fatalf("injection to a refused target: %d %v, want 502 with the reason", code, err)
	}
}

// A name that resolves to several addresses: none refused is ever dialled; one that isn't is.
func TestEveryAddressANameResolvesToIsChecked(t *testing.T) {
	r := newNameRig(t, nil)
	r.answer(addrs("127.0.0.1", "10.0.0.5", "203.0.113.9", "::1"))
	if !r.passes() {
		t.Fatal("the public address among the answers wasn't used")
	}
	if dialled, _ := r.seen(); !slices.Equal(dialled, []string{"203.0.113.9"}) {
		t.Fatalf("dialled %v, want only 203.0.113.9", dialled)
	}
}

// DNS rebinding: a name that answers a public address and then a private one. Each connection
// is checked on what it dials, so the second answer is refused however the first went.
func TestARebindingNameIsRefusedAtConnectTime(t *testing.T) {
	r := newNameRig(t, nil)
	r.answer(addrs("203.0.113.9"), addrs("127.0.0.1"))
	if !r.passes() {
		t.Fatal("first answer (public) refused")
	}
	if r.passes() {
		t.Fatal("second answer (loopback) passed")
	}
	if dialled, _ := r.seen(); !slices.Equal(dialled, []string{"203.0.113.9"}) {
		t.Fatalf("dialled %v", dialled)
	}
	// Within one injection, the upstream connection is dialled on its own answer too.
	r.answer(addrs("127.0.0.1"))
	if code, err := r.injects(); err == nil && code == 200 {
		t.Fatal("an injection dialled a rebound name")
	}
	if dialled, _ := r.seen(); len(dialled) != 0 {
		t.Fatalf("dialled %v", dialled)
	}
}

// A grant that names the address itself (a CIDR rule inside the refused range, for the port)
// opens it; one wider than the range (0.0.0.0/0) does not name it.
func TestAnAddressTheGrantNamesIsAllowed(t *testing.T) {
	r := newNameRig(t, nil, v1.EgressRule{To: "10.1.2.0/24", Ports: []string{"443"}}, v1.EgressRule{To: "0.0.0.0/0", Ports: []string{"443"}})
	r.answer(addrs("10.1.2.3"))
	if !r.passes() {
		t.Fatal("an address the grant names was refused")
	}
	for _, target := range []string{"10.1.3.1", "127.0.0.1", "169.254.169.254"} {
		r.answer(addrs(target))
		if r.passes() {
			t.Errorf("%s passed: only 0.0.0.0/0 covers it, which doesn't name it", target)
		}
	}
	// Named for another port only: not for this one.
	r = newNameRig(t, nil, v1.EgressRule{To: "10.1.2.3/32", Ports: []string{"22"}})
	r.answer(addrs("10.1.2.3"))
	if r.passes() {
		t.Error("an address named for port 22 was passed on 443")
	}
}

// The host's own addresses, and others the worker knows are the cluster's (Gate.Internal), are
// refused like private ones, and opened only when a grant names exactly that address.
func TestTheClustersOwnAddressesAreRefused(t *testing.T) {
	own := []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32"), netip.MustParsePrefix("2001:db8::10/128")}
	r := newNameRig(t, own)
	for _, target := range []string{"198.51.100.10", "2001:db8::10", "::ffff:198.51.100.10"} {
		r.answer(addrs(target))
		if r.passes() {
			t.Errorf("the host's own %s was passed", target)
		}
	}
	r.answer(addrs("198.51.100.11"))
	if !r.passes() {
		t.Error("a neighbour of the host's address was refused")
	}
	r = newNameRig(t, own, v1.EgressRule{To: "198.51.100.0/24", Ports: []string{"443"}})
	r.answer(addrs("198.51.100.10"))
	if r.passes() {
		t.Error("a /24 around the host's own address named it")
	}
	r = newNameRig(t, own, v1.EgressRule{To: "198.51.100.10/32", Ports: []string{"443"}})
	r.answer(addrs("198.51.100.10"))
	if !r.passes() {
		t.Error("the host's address named exactly was refused")
	}
}

// The gate's own dialer checks the socket's address again when it connects for a name. A CIDR
// rule still dials an ordinary private address, and does not dial loopback.
func TestTheDefaultDialerChecksAtConnectTime(t *testing.T) {
	g := &Gate{}
	check := g.atConnect(Policy{})
	for addr, refused := range map[string]bool{"127.0.0.1:443": true, "[::1]:443": true, "10.64.0.7:443": true, "[fe80::1%eth0]:443": true, "203.0.113.9:443": false} {
		if err := check("tcp4", addr, nil); (err != nil) != refused {
			t.Errorf("at connect, %s: %v", addr, err)
		}
	}
	l, err := net.Listen("tcp", net.JoinHostPort(localPrivate(t).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if c, err := g.dial(context.Background(), Policy{}, l.Addr().String(), false); err != nil {
		t.Fatalf("a CIDR passthrough was refused: %v", err)
	} else {
		_ = c.Close()
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	g.Resolve = func(context.Context, string) ([]netip.Addr, error) { return addrs("127.0.0.1"), nil }
	if c, err := g.dial(context.Background(), Policy{}, net.JoinHostPort("x.test", port), true); err == nil {
		_ = c.Close()
		t.Fatal("a name dialled loopback through the default dialer")
	}
}
