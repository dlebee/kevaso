package v1

import (
	"net/netip"
	"testing"
)

func TestFamilyOf(t *testing.T) {
	for a, want := range map[string]string{
		"203.0.113.7": FamilyIPv4, "2001:db8::7": FamilyIPv6, "::ffff:1.2.3.4": FamilyIPv6, "": "", "nope": "", "10.0.0.0/8": "",
	} {
		if got := FamilyOf(a); got != want {
			t.Errorf("FamilyOf(%q) = %q, want %q", a, got, want)
		}
	}
	if (IPSpec{}).FamilyOrDefault() != FamilyIPv4 || (IPSpec{Family: FamilyIPv6}).FamilyOrDefault() != FamilyIPv6 {
		t.Fatal("an IP is IPv4 unless it says IPv6")
	}
	if (HostAddress{Address: "2001:db8::5"}).Family() != FamilyIPv6 {
		t.Fatal("a host's IPv6 address is IPv6")
	}
}

// A grant never opens the IPv6 addresses that are no peer on the internet, as for IPv4.
func TestClosedRangeIPv6(t *testing.T) {
	for s, closed := range map[string]bool{
		"::/128": true, "::1/128": true, "fe80::/64": true, "ff02::1/128": true,
		"2001:db8::/32": false, "::/0": false, "2600::/16": false,
	} {
		_, why := ClosedRange(netip.MustParsePrefix(s))
		if (why != "") != closed {
			t.Errorf("ClosedRange(%s) = %q, want closed %v", s, why, closed)
		}
	}
}
