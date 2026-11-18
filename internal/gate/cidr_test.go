package gate

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A CIDR rule is judged before it is dialled. 0.0.0.0/0 still dials a public address and a
// private address a grant may name. It does not dial a closed range, or this host's own address
// unless the grant names that address.
func TestWideCIDRDoesNotDialAClosedRange(t *testing.T) {
	var dialled []string
	g := &Gate{
		Internal: func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("198.51.100.10/32")} },
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			return nil, errors.New("dialled")
		},
	}
	s := &v1.Silo{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "web"}, Spec: v1.SiloSpec{Grants: []string{"g"}}}
	wide := &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "g"},
		Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "0.0.0.0/0", Ports: []string{"80"}}}}}
	pol := PolicyFor(s, []*v1.Grant{wide})
	for _, addr := range []string{
		"169.254.169.254:80", "127.0.0.1:80", "0.0.0.0:80", "0.1.2.3:80",
		"224.0.0.1:80", "240.0.0.1:80", "255.255.255.255:80", "[ff02::1]:80",
		"198.51.100.10:80",
	} {
		dialled = nil
		_, err := g.dial(context.Background(), pol, addr, false)
		if err == nil || !strings.Contains(err.Error(), "which a grant never opens") {
			t.Errorf("%s: %v", addr, err)
		}
		if len(dialled) != 0 {
			t.Errorf("%s was dialled: %v", addr, dialled)
		}
	}
	for _, addr := range []string{"203.0.113.9:80", "10.1.2.3:80"} {
		dialled = nil
		_, err := g.dial(context.Background(), pol, addr, false)
		if len(dialled) != 1 || dialled[0] != addr {
			t.Errorf("%s: dialled %v (%v)", addr, dialled, err)
		}
	}
	named := &v1.Grant{ObjectMeta: meta.ObjectMeta{Namespace: "dev", Name: "g"},
		Spec: v1.GrantSpec{Egress: []v1.EgressRule{{To: "198.51.100.10/32", Ports: []string{"80"}}}}}
	pol = PolicyFor(s, []*v1.Grant{named})
	dialled = nil
	if _, err := g.dial(context.Background(), pol, "198.51.100.10:80", false); len(dialled) != 1 {
		t.Fatalf("the grant names this host's address, and it was not dialled (%v, %v)", dialled, err)
	}
}
