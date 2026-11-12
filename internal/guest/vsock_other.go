//go:build !linux

package guest

import (
	"errors"
	"net"
)

func dialVsock(uint32) (net.Conn, error) {
	return nil, errors.New("vsock: only inside a Linux silo (set KVO_GUEST_BROKER=unix:PATH to test)")
}
