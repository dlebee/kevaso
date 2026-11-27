package worker

import (
	"context"
	"net/netip"
	"os/exec"
	"slices"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// A Provider IP is on a host only where it holds it: on the loopback when its provider announces
// it, on the uplink otherwise, and nowhere on a host that doesn't hold it. Something else may put
// one there all the same: Linode's Network Helper writes a reserved IPv4's assignment into the
// boot config, so its first holder, rebooted after the silo moved, comes up with the address on
// eth0 (and answers ARP for it). strayProviderAddresses finds those; dropStrayProviderAddresses,
// run at start and on every sync, removes them.

// ifaceAddr is one address on one interface, as `ip -o addr` shows it.
type ifaceAddr struct {
	Iface  string
	Prefix netip.Prefix
}

// strayProviderAddresses are the addresses in have that belong to a Provider IP (ips) and aren't
// where this host holds them: allowed maps an interface to the addresses wanted there.
func strayProviderAddresses(have []ifaceAddr, ips []*v1.IP, allowed map[string][]string) []ifaceAddr {
	provider := map[netip.Addr]bool{}
	for _, x := range ips {
		if x.Spec.Type != v1.IPTypeProvider || x.Status.Address == "" {
			continue
		}
		if a, err := netip.ParseAddr(x.Status.Address); err == nil {
			provider[a.Unmap()] = true
		}
	}
	var out []ifaceAddr
	for _, h := range have {
		a := h.Prefix.Addr().Unmap()
		if !provider[a] || slices.Contains(allowed[h.Iface], a.String()) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// parseIPAddr reads `ip -o addr show` (both families): one ifaceAddr per inet/inet6 line.
func parseIPAddr(out string) []ifaceAddr {
	var have []ifaceAddr
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || (f[2] != "inet" && f[2] != "inet6") {
			continue
		}
		p, err := netip.ParsePrefix(f[3])
		if err != nil {
			continue
		}
		have = append(have, ifaceAddr{Iface: strings.TrimSuffix(f[1], ":"), Prefix: p})
	}
	return have
}

// listAddresses lists every address on every interface (tests replace it).
var listAddresses = func(ctx context.Context) ([]ifaceAddr, error) {
	out, err := exec.CommandContext(ctx, "ip", "-o", "addr", "show").Output()
	if err != nil {
		return nil, err
	}
	return parseIPAddr(string(out)), nil
}

// delAddress removes one address from an interface (tests replace it).
var delAddress = func(ctx context.Context, a ifaceAddr) error {
	if b, err := exec.CommandContext(ctx, "ip", "addr", "del", a.Prefix.String(), "dev", a.Iface).CombinedOutput(); err != nil {
		return &cmdError{"ip addr del " + a.Prefix.String() + " dev " + a.Iface, err, string(b)}
	}
	return nil
}

// dropStrayProviderAddresses removes every Provider IP's address from where this host doesn't
// hold it, whoever put it there, and says what it removed.
func dropStrayProviderAddresses(ctx context.Context, ips []*v1.IP, allowed map[string][]string) ([]ifaceAddr, error) {
	have, err := listAddresses(ctx)
	if err != nil {
		return nil, err
	}
	var gone []ifaceAddr
	for _, a := range strayProviderAddresses(have, ips, allowed) {
		if err := delAddress(ctx, a); err != nil {
			return gone, err
		}
		gone = append(gone, a)
	}
	return gone, nil
}
