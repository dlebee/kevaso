package worker

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// What `ip -o addr show` printed on a Linode worker rebooted after its silo moved away: Network
// Helper put the reserved IPv4 172.105.98.21 (assigned to it, now held by another worker) on eth0
// as a /24. The Provider IP it holds now (announced) is on lo, labelled ours.
const rebootedLinode = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
1: lo    inet 172.105.99.7/32 scope global lo:kv\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \       valid_lft forever preferred_lft forever
2: eth0    inet 172.105.6.54/24 brd 172.105.6.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet 172.105.98.21/24 brd 172.105.98.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.131.29/17 brd 192.168.255.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet6 2600:3c04::2000:f0ff:fe65:dff6/64 scope global dynamic mngtmpaddr \       valid_lft 5000sec preferred_lft 1000sec
4: kvbr0    inet 10.64.2.1/24 brd 10.64.2.255 scope global kvbr0\       valid_lft forever preferred_lft forever
`

func providerIP(addr string, announce bool) *v1.IP {
	return &v1.IP{Spec: v1.IPSpec{Type: v1.IPTypeProvider, Provider: "linode", Region: "ca-central"}, Status: v1.IPStatus{Address: addr, Announce: announce}}
}

func TestParseIPAddr(t *testing.T) {
	got := parseIPAddr(rebootedLinode)
	if len(got) != 8 {
		t.Fatalf("%d addresses: %v", len(got), got)
	}
	if got[4] != (ifaceAddr{Iface: "eth0", Prefix: netip.MustParsePrefix("172.105.98.21/24")}) || got[1].Iface != "lo" || got[7].Iface != "kvbr0" {
		t.Errorf("parsed %v", got)
	}
}

// A Provider IP is only where the host holds it: the one on eth0 that this host doesn't hold goes
// (whoever put it there, whatever its prefix); the held one on lo stays; the host's own addresses
// and an IP of another type are never touched.
func TestStrayProviderAddresses(t *testing.T) {
	ips := []*v1.IP{
		providerIP("172.105.98.21", true), // moved to another worker
		providerIP("172.105.99.7", true),  // held here, announced: on lo
		providerIP("172.105.97.3", false), // held here, not announced: on the uplink
		{Spec: v1.IPSpec{Type: v1.IPTypeHost, HostAddress: "main"}, Status: v1.IPStatus{Address: "172.105.6.54"}},
		providerIP("", true), // not reserved yet
	}
	have := parseIPAddr(rebootedLinode)
	have = append(have,
		ifaceAddr{"eth0", netip.MustParsePrefix("172.105.97.3/32")}, // held, on the uplink: stays
		ifaceAddr{"lo", netip.MustParsePrefix("172.105.97.3/32")},   // held on the uplink, not on lo: goes
		ifaceAddr{"eth0", netip.MustParsePrefix("172.105.99.7/32")}, // held on lo, not on eth0: goes
	)
	allowed := map[string][]string{"lo": {"172.105.99.7"}, "eth0": {"172.105.97.3"}}
	got := fmt.Sprint(strayProviderAddresses(have, ips, allowed))
	want := "[{eth0 172.105.98.21/24} {lo 172.105.97.3/32} {eth0 172.105.99.7/32}]"
	if got != want {
		t.Errorf("stray %s\nwant  %s", got, want)
	}
	// A host holding nothing has no Provider IP anywhere.
	if got := strayProviderAddresses(have, ips, nil); len(got) != 5 {
		t.Errorf("holding nothing: %v", got)
	}
	// No Provider IPs known (the cache not filled yet): nothing is touched.
	if got := strayProviderAddresses(have, nil, nil); len(got) != 0 {
		t.Errorf("no IPs known: %v", got)
	}
}

// At start and on every sync the stray ones are removed, and only those.
func TestDropStrayProviderAddresses(t *testing.T) {
	list, del := listAddresses, delAddress
	t.Cleanup(func() { listAddresses, delAddress = list, del })
	listAddresses = func(context.Context) ([]ifaceAddr, error) { return parseIPAddr(rebootedLinode), nil }
	var deleted []ifaceAddr
	delAddress = func(_ context.Context, a ifaceAddr) error { deleted = append(deleted, a); return nil }
	ips := []*v1.IP{providerIP("172.105.98.21", true), providerIP("172.105.99.7", true)}
	gone, err := dropStrayProviderAddresses(context.Background(), ips, map[string][]string{"lo": {"172.105.99.7"}})
	if err != nil || fmt.Sprint(gone) != "[{eth0 172.105.98.21/24}]" || fmt.Sprint(deleted) != fmt.Sprint(gone) {
		t.Fatalf("gone %v deleted %v %v", gone, deleted, err)
	}
}
