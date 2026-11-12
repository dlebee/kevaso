package guest

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// dialVsock connects to the host (CID 2) on port: Cloud Hypervisor hands it to the silo's own
// socket on the host, which is how the broker knows who's calling.
func dialVsock(port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock: %w (is this a Kevaso VM?)", err)
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("vsock to the host, port %d: %w", port, err)
	}
	// net.FileConn doesn't know AF_VSOCK; an os.File on a non-blocking fd uses the runtime poller,
	// so reads, writes and deadlines work as on any connection.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &vsockConn{File: os.NewFile(uintptr(fd), "vsock"), port: port}, nil
}

type vsockConn struct {
	*os.File
	port uint32
}

type vsockAddr struct{ cid, port uint32 }

func (vsockAddr) Network() string         { return "vsock" }
func (a vsockAddr) String() string        { return fmt.Sprintf("%d:%d", a.cid, a.port) }
func (c *vsockConn) LocalAddr() net.Addr  { return vsockAddr{unix.VMADDR_CID_ANY, 0} }
func (c *vsockConn) RemoteAddr() net.Addr { return vsockAddr{unix.VMADDR_CID_HOST, c.port} }

func (c *vsockConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }
