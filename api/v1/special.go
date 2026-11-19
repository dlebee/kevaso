package v1

import "net/netip"

// special are the ranges a host name never leads to, and a disk is never fetched from: the host
// itself, its networks and the cluster's (all of 10/8: the mesh, silos and services are in it),
// and nothing the internet can route to. IPv6 forms that carry an IPv4 address are checked on
// that address.
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

// Special says whether a host name may never lead to a, and why: the smallest range of the
// refused ones holding it, else "" (an ordinary internet address). Pure. The egress gate uses
// this, and so does a VM disk fetch: a built-in plugin cannot import the gate.
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
