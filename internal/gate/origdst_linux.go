package gate

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// OriginalDst is where a connection redirected by nftables was going (SO_ORIGINAL_DST).
func OriginalDst(c net.Conn) (netip.AddrPort, error) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.AddrPort
	var serr error
	err = raw.Control(func(fd uintptr) {
		// struct sockaddr_in through the IPv6 mreq getter: the usual way to read it from Go.
		m, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, unix.SO_ORIGINAL_DST)
		if err != nil {
			serr = err
			return
		}
		b := m.Multiaddr
		port := binary.BigEndian.Uint16(b[2:4])
		addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port)
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	return addr, serr
}
