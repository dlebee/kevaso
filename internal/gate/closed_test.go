package gate

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/mesh"
)

// K-124: a grant never opens the cluster's own ranges (silos, services, the mesh), loopback or
// link-local through the egress gate, whatever the grant says. The gate refuses such an address
// when a name resolves to it and again at connect time. A private address outside those ranges is
// still opened only when the grant names it (K-057), and a public address is unchanged. A grant of
// 0.0.0.0/0 does not open the host's own public addresses, and naming 169.254.169.254 does not
// open a cloud's metadata address: the same refusal covers both.

func TestTheEgressGateNeverOpensClusterLoopbackOrLinkLocal(t *testing.T) {
	// The grant names each closed address, the ranges themselves, a wide private range, and
	// 0.0.0.0/0. It also names an ordinary private address, which stays allowed.
	rules := []v1.EgressRule{
		{To: "0.0.0.0/0", Ports: []string{"443"}},
		{To: "10.0.0.0/8", Ports: []string{"443"}},
		{To: "10.1.2.0/24", Ports: []string{"443"}},
		{To: "192.168.1.0/24", Ports: []string{"443"}},
		{To: "10.64.2.5", Ports: []string{"443"}},
		{To: "10.64.0.0/16", Ports: []string{"443"}},
		{To: "10.65.0.9", Ports: []string{"443"}},
		{To: "10.65.0.0/16", Ports: []string{"443"}},
		{To: "10.63.0.4", Ports: []string{"443"}},
		{To: "10.63.0.0/16", Ports: []string{"443"}},
		{To: "10.62.0.4", Ports: []string{"443"}},
		{To: "10.62.0.0/16", Ports: []string{"443"}},
		{To: "127.0.0.1", Ports: []string{"443"}},
		{To: "127.0.0.0/8", Ports: []string{"443"}},
		{To: "169.254.169.254", Ports: []string{"443"}},
		{To: "169.254.42.1", Ports: []string{"443"}},
		{To: "169.254.0.0/16", Ports: []string{"443"}},
	}
	own := []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")}
	r := newNameRig(t, own, rules...)

	r.answer(addrs("203.0.113.9"))
	if !r.passes() {
		t.Fatal("a public address was refused")
	}
	if code, err := r.injects(); err != nil || code != 200 {
		t.Fatalf("a public address was refused for an injection: %d %v", code, err)
	}
	for _, target := range []string{"10.1.2.3", "192.168.1.9"} {
		r.answer(addrs(target))
		if !r.passes() {
			t.Errorf("private %s, which the grant names, was refused", target)
		}
	}

	// Named by the grant, and still never dialled. The host's own public address is covered only
	// by 0.0.0.0/0, which does not name it.
	closed := []string{
		"10.64.2.5", "10.64.0.1", "10.65.0.9", "10.63.0.4", "10.62.0.4",
		"127.0.0.1", "127.8.9.10", "::1",
		"169.254.169.254", "169.254.42.1", "fe80::1",
		"::ffff:127.0.0.1", "::ffff:10.64.2.5", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::1", "2002:a9fe:a9fe::1",
		"198.51.100.10", "::ffff:198.51.100.10",
	}
	for _, target := range closed {
		r.answer(addrs(target))
		if r.passes() {
			t.Errorf("%s was opened through the gate", target)
		}
		if code, err := r.injects(); err == nil && code == 200 {
			t.Errorf("%s got a secret injected", target)
		}
		dialled, log := r.seen()
		if len(dialled) > 0 {
			t.Errorf("%s: the gate dialled %v", target, dialled)
		}
		want := "which a grant never opens"
		if target == "198.51.100.10" || target == "::ffff:198.51.100.10" {
			want = "which a name never leads to" // the host's own public address (K-057)
		}
		if !strings.Contains(log, netip.MustParseAddr(target).String()) || !strings.Contains(log, want) {
			t.Errorf("%s: the refusal doesn't name the address (%q):\n%s", target, want, log)
		}
	}

	// Connect time: the socket's address is refused again, grant or not.
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "claude-1"}, Spec: v1.SiloSpec{Grants: []string{"g"}}}
	gnt := &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "g"}, Spec: v1.GrantSpec{Egress: rules}}
	pol := PolicyFor(s, []*v1.Grant{gnt})
	g := &Gate{Internal: func() []netip.Prefix { return own }}
	check := g.atConnect(pol)
	for _, addr := range []string{
		"10.64.2.5:443", "10.65.0.9:443", "10.63.0.4:443", "10.62.0.4:443",
		"127.0.0.1:443", "[::1]:443", "169.254.169.254:443", "169.254.42.1:443", "[fe80::1%eth0]:443",
		"198.51.100.10:443",
	} {
		if err := check("tcp", addr, nil); err == nil {
			t.Errorf("at connect, %s was allowed", addr)
		}
	}
	for _, addr := range []string{"10.1.2.3:443", "192.168.1.9:443", "203.0.113.9:443"} {
		if err := check("tcp", addr, nil); err != nil {
			t.Errorf("at connect, %s was refused: %v", addr, err)
		}
	}
	// The default dialer's connect-time check is atConnect. A name that resolves to metadata is
	// refused before anything is dialled.
	g.Resolve = func(context.Context, string) ([]netip.Addr, error) { return addrs("169.254.169.254"), nil }
	g.Dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("the gate dialled 169.254.169.254")
		return nil, errors.New("dialled")
	}
	if _, err := g.dial(context.Background(), pol, "metadata.test:443", true); err == nil || !strings.Contains(err.Error(), "which a grant never opens") {
		t.Errorf("a name resolving to 169.254.169.254: %v", err)
	}
}

// The ranges a grant never opens are the mesh's, the service range and the network model's.
func TestClosedRangesFollowTheMeshAndTheNetworkModel(t *testing.T) {
	want := []string{mesh.InnerPrefix.String(), mesh.MeshPrefix.String(), mesh.SiloPrefix.String(), v1.ServiceCIDR}
	if !slices.Equal(want, v1.KevasoRanges) {
		t.Fatalf("mesh and service %v, KevasoRanges %v", want, v1.KevasoRanges)
	}
	for _, s := range append(want, "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10") {
		if _, why := v1.ClosedRange(netip.MustParsePrefix(s)); why == "" {
			t.Errorf("%s is not a range a grant never opens", s)
		}
	}
	for _, s := range []string{"10.0.0.0/8", "0.0.0.0/0", "192.168.0.0/16", "198.51.100.10/32"} {
		if _, why := v1.ClosedRange(netip.MustParsePrefix(s)); why != "" {
			t.Errorf("%s is closed to grants (%s)", s, why)
		}
	}
}
