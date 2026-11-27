package mesh

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IPv6 at the edge (the IPv6 effort): the mesh stays IPv4. Each cluster has one random unique
// local /48 (RFC 4193: fd00::/8 and 40 random bits), assigned once and stored by the control plane.
// Host index n gets the /64 whose subnet ID is n (fdXX:XXXX:XXXX:n::/64), beside its IPv4
// siloSubnet; a silo gets one address in it, derived from its IPv4 one: the same host part. The
// /64s are never routed over the mesh: a silo goes out by NAT66 and is reached by DNAT, like IPv4.

// ulaBits is the size of the cluster's IPv6 range.
const ulaBits = 48

// NewULA is a fresh random unique local /48 (fd00::/8, a 40-bit random global ID).
func NewULA() netip.Prefix {
	var b [16]byte
	b[0] = 0xfd
	if _, err := rand.Read(b[1:6]); err != nil {
		panic(err) // crypto/rand doesn't fail on supported systems
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), ulaBits)
}

// CheckULA says why p can't be a cluster's IPv6 range (nil when it can): a /48 inside fd00::/8.
func CheckULA(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != ulaBits || p.Masked() != p {
		return fmt.Errorf("%s: a cluster's IPv6 range is one /48 (fdXX:XXXX:XXXX::/48)", p)
	}
	if p.Addr().As16()[0] != 0xfd {
		return fmt.Errorf("%s: a cluster's IPv6 range is a unique local /48 in fd00::/8", p)
	}
	return nil
}

// SubnetIPv6 is host index n's silo /64 in the cluster's ULA ula ("" if ula isn't one, or n is
// out of range).
func SubnetIPv6(ula string, n int) string {
	p, err := netip.ParsePrefix(ula)
	if err != nil || CheckULA(p) != nil || n < 0 || n > MaxHosts {
		return ""
	}
	b := p.Addr().As16()
	binary.BigEndian.PutUint16(b[6:8], uint16(n))
	return netip.PrefixFrom(netip.AddrFrom16(b), 64).String()
}

// SiloIPv6 is the IPv6 address of the silo whose IPv4 address is siloIP in subnet (the host's
// siloSubnet), in the host's IPv6 /64 subnet6: the same host part (10.64.3.17 in 10.64.3.0/24 is
// …:3::11). ok false when one of them doesn't parse or siloIP isn't in subnet.
func SiloIPv6(subnet6, subnet, siloIP string) (string, bool) {
	p6, err6 := netip.ParsePrefix(subnet6)
	p4, err4 := netip.ParsePrefix(subnet)
	a, erra := netip.ParseAddr(siloIP)
	if err6 != nil || err4 != nil || erra != nil || !p6.Addr().Is6() || p6.Addr().Is4In6() || p6.Bits() != 64 ||
		!p4.Addr().Is4() || !a.Is4() || !p4.Contains(a) {
		return "", false
	}
	v4 := a.As4()
	hostBits := binary.BigEndian.Uint32(v4[:]) & (1<<(32-p4.Bits()) - 1)
	b := p6.Masked().Addr().As16()
	binary.BigEndian.PutUint32(b[12:16], hostBits)
	return netip.AddrFrom16(b).String(), true
}
