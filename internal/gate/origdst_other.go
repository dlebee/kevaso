//go:build !linux

package gate

import (
	"errors"
	"net"
	"net/netip"
)

// OriginalDst needs Linux (nftables redirect).
func OriginalDst(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("the egress gate runs on Linux only")
}
