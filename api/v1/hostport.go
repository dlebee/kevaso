package v1

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// AnnotationSSH is how an operator reaches a host (USER@ADDRESS:PORT). kvoadm writes it; the port,
// when it is not 22, is one a silo may not take. 22 itself is always reserved.
const AnnotationSSH = "kevaso.com/ssh"

// ReservedHostPort says why n is a number the platform listens on, so no silo may take it as a
// host port, on TCP or UDP. Empty means a silo may. 80 and 443 are not reserved: serving on them
// is a documented use of a host port, and the built-in ingress controller uses them.
//
// The numbers are the platform's listeners: SSH, DNS, etcd, the API, the mesh (outer and inner)
// and the egress gate. A host that listens elsewhere adds its own in ExtraReservedPorts.
func ReservedHostPort(n int) string {
	switch n {
	case 22:
		return "the SSH port"
	case 53:
		return "DNS"
	case 2379, 2380:
		return "etcd"
	case 6443:
		return "the API"
	case 51820, 51821:
		return "the mesh"
	case 15001:
		return "the egress gate"
	default:
		return ""
	}
}

// SSHPort is the port in the host's SSH annotation, or 0 when it has none or it doesn't parse.
func SSHPort(h *Host) int {
	if h == nil || h.Annotations == nil {
		return 0
	}
	v := h.Annotations[AnnotationSSH]
	_, hostport, ok := strings.Cut(v, "@")
	if !ok {
		return 0
	}
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// ExtraReservedPorts are host-port numbers this host uses beyond ReservedHostPort, and why: its
// mesh listen port, its SSH port, and the API and etcd ports it publishes. A number ReservedHostPort
// already explains is left out, so that reason stands.
func (h *Host) ExtraReservedPorts() map[int]string {
	if h == nil {
		return nil
	}
	out := map[int]string{}
	add := func(n int, why string) {
		if n < 1 || n > 65535 || ReservedHostPort(n) != "" {
			return
		}
		if _, seen := out[n]; !seen {
			out[n] = why
		}
	}
	add(h.Spec.Network.ListenPort, "the mesh")
	add(SSHPort(h), "the SSH port")
	if cp := h.Status.ControlPlane; cp != nil {
		add(portOfURL(cp.APIURL), "the API")
		add(portOfURL(cp.PeerURL), "etcd")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func portOfURL(raw string) int {
	if raw == "" {
		return 0
	}
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	p := u.Port()
	if p == "" {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}
