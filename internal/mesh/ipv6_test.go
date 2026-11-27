package mesh

import (
	"net/netip"
	"testing"
)

func TestNewULAIsARandomUniqueLocal48(t *testing.T) {
	a, b := NewULA(), NewULA()
	for _, p := range []netip.Prefix{a, b} {
		if err := CheckULA(p); err != nil {
			t.Fatalf("NewULA %s: %v", p, err)
		}
	}
	if a == b {
		t.Fatalf("two clusters got the same /48 %s: the global ID is random", a)
	}
}

func TestCheckULA(t *testing.T) {
	for s, ok := range map[string]bool{
		"fd12:3456:789a::/48":    true,
		"fc12:3456:789a::/48":    false, // fc00::/8 is not for local assignment
		"fd12:3456:789a::/56":    false,
		"fd12:3456:789a:1::/48":  false, // not masked
		"2001:db8::/48":          false,
		"10.64.0.0/16":           false,
		"::ffff:10.64.0.0/112":   false,
		"fd12:3456:789a::/64":    false,
		"fd00:0000:0000::/48":    true,
		"fdff:ffff:ffff::/48":    true,
		"fd12:3456:789b::1/48":   false,
		"fd12:3456:789a::/47":    false,
		"fd12:3456:789a:ff::/48": false,
	} {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		if got := CheckULA(p) == nil; got != ok {
			t.Errorf("CheckULA(%s) ok = %v, want %v", s, got, ok)
		}
	}
}

func TestSubnetIPv6ByIndex(t *testing.T) {
	const ula = "fd12:3456:789a::/48"
	for n, want := range map[int]string{0: "fd12:3456:789a::/64", 1: "fd12:3456:789a:1::/64", 3: "fd12:3456:789a:3::/64", 255: "fd12:3456:789a:ff::/64"} {
		if got := SubnetIPv6(ula, n); got != want {
			t.Errorf("SubnetIPv6(%d) = %q, want %q", n, got, want)
		}
	}
	for _, bad := range []struct {
		ula string
		n   int
	}{{"", 1}, {"2001:db8::/48", 1}, {ula, 256}, {ula, -1}} {
		if got := SubnetIPv6(bad.ula, bad.n); got != "" {
			t.Errorf("SubnetIPv6(%q, %d) = %q, want none", bad.ula, bad.n, got)
		}
	}
}

func TestSiloIPv6KeepsTheHostPart(t *testing.T) {
	for _, tc := range []struct {
		subnet6, subnet, ip, want string
		ok                        bool
	}{
		{"fd12:3456:789a:3::/64", "10.64.3.0/24", "10.64.3.17", "fd12:3456:789a:3::11", true},
		{"fd12:3456:789a:3::/64", "10.64.3.0/24", "10.64.3.2", "fd12:3456:789a:3::2", true},
		{"fd12:3456:789a::/64", "10.64.0.0/24", "10.64.0.254", "fd12:3456:789a::fe", true},
		{"fd12:3456:789a:3::/64", "10.64.3.0/24", "10.64.4.17", "", false}, // another host's
		{"fd12:3456:789a:3::/56", "10.64.3.0/24", "10.64.3.17", "", false},
		{"", "10.64.3.0/24", "10.64.3.17", "", false},
		{"fd12:3456:789a:3::/64", "10.64.3.0/24", "fd12::1", "", false},
	} {
		got, ok := SiloIPv6(tc.subnet6, tc.subnet, tc.ip)
		if got != tc.want || ok != tc.ok {
			t.Errorf("SiloIPv6(%s, %s, %s) = %q, %v; want %q, %v", tc.subnet6, tc.subnet, tc.ip, got, ok, tc.want, tc.ok)
		}
	}
}
