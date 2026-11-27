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

// An IPv6 port status is "[ADDRESS]:PORT": the address is read whole, not cut at its first colon.
func TestOutsideAddressesOfIPv6Ports(t *testing.T) {
	st := SiloServiceStatus{
		Ports: []ServicePortStatus{
			{Port: "web", External: "[2001:db8:20::21]:8080"},
			{Port: "api", Internal: "10.0.0.5:443", External: "[2001:db8:20::21]:8443"},
		},
		EgressIP: "203.0.113.10",
	}
	if got := st.OutsideIPs(); len(got) != 2 || got[0] != "2001:db8:20::21" || got[1] != "10.0.0.5" {
		t.Errorf("OutsideIPs = %q, want [2001:db8:20::21 10.0.0.5]", got)
	}
	if got, want := st.AddressesLine(), "in 2001:db8:20::21, 10.0.0.5, out 203.0.113.10"; got != want {
		t.Errorf("AddressesLine = %q, want %q", got, want)
	}
	if got := st.Front(); got != "2001:db8:20::21" {
		t.Errorf("Front = %q, want 2001:db8:20::21 (an IPv6-only service's front is its whole address)", got)
	}
	if got := (SiloServiceStatus{Ports: []ServicePortStatus{{Port: "x", External: "garbage"}}}).Front(); got != "" {
		t.Errorf("Front of no address = %q, want empty", got)
	}
}
