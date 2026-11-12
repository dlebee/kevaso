package guest

import (
	"fmt"
	"net"
	"os"

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
	f := os.NewFile(uintptr(fd), "vsock")
	defer func() { _ = f.Close() }()
	return net.FileConn(f)
}
