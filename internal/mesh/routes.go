package mesh

import (
	"net"
	"slices"
	"sort"
)

// routePlan says which routes to add and which to remove so an interface carries exactly want,
// given what this process added before (have). Pure; the macOS backend, which has no netlink,
// routes with route(8) and keeps its own list.
func routePlan(have, want []string) (add, del []string) {
	for _, w := range want {
		if !slices.Contains(have, w) {
			add = append(add, w)
		}
	}
	for _, h := range have {
		if !slices.Contains(want, h) {
			del = append(del, h)
		}
	}
	sort.Strings(add)
	sort.Strings(del)
	return add, del
}

// networkOf is the network of an interface address with its prefix ("10.63.0.3/16" is
// "10.63.0.0/16"): what the whole mesh is reached through.
func networkOf(addr string) (string, error) {
	_, n, err := net.ParseCIDR(addr)
	if err != nil {
		return "", err
	}
	return n.String(), nil
}

// hostOf is the address of an interface address without its prefix.
func hostOf(addr string) (string, error) {
	ip, _, err := net.ParseCIDR(addr)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// ifconfigArgs gives a utun interface its address (a point-to-point /32, as wg-quick does on a
// Mac: the mesh's own prefix is a route, not part of the address), its MTU, and brings it up.
func ifconfigArgs(utun, host string, mtu int) [][]string {
	out := [][]string{{"ifconfig", utun, "inet", host + "/32", host, "alias"}}
	if mtu > 0 {
		out = append(out, []string{"ifconfig", utun, "mtu", itoa(mtu)})
	}
	return append(out, []string{"ifconfig", utun, "up"})
}

func routeArgs(op, cidr, utun string) []string {
	return []string{"route", "-q", "-n", op, "-inet", cidr, "-interface", utun}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
