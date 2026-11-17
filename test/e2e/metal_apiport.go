package e2e

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// metalAPIPort is the port this Mac dials for machine 1's API.
// KEVASO_METAL_API_PORT is a pair lab's slot port; unset means 6443, the port a real machine listens on.
func metalAPIPort() (string, error) {
	p := os.Getenv("KEVASO_METAL_API_PORT")
	if p == "" {
		return "6443", nil
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("KEVASO_METAL_API_PORT %q: want a TCP port", p)
	}
	return strconv.Itoa(n), nil
}

// metalAPIServer is the URL kvoadm --api-server and kvo use for that port.
func metalAPIServer(ip, port string) string {
	return "https://" + net.JoinHostPort(ip, port)
}

// metalAPIServerFor is the URL this Mac uses for machine 1's API, and the one
// kvoadm init records in kvo's config. A real machine (port 6443) is
// https://external:6443. A pair lab publishes 6443 on the lab host at the slot
// port; the machine's external address is on the lab's external bridge, which
// this Mac does not route. The worker does not use this URL: a second machine
// dials https://external:6443 on that bridge, passed as --server.
func metalAPIServerFor(external, sshAddr, port string) string {
	host := external
	if port != "6443" {
		host = sshAddr
	}
	return metalAPIServer(host, port)
}

// metalAPIDropPorts are the ports a cut of machine 2's path to the API has to drop: the one the
// tests dial, and 6443 when that is different. The control plane advertises its listen port
// (6443; kvoadm has no flag to change it), and the worker's tunnel dials that URL.
func metalAPIDropPorts(port string) []string {
	if port == "6443" {
		return []string{"6443"}
	}
	return []string{port, "6443"}
}
