//go:build linux

package mesh

import (
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Apply makes the host's interfaces match d: kernel WireGuard through netlink and wgctrl, no
// wg-quick, no daemon (E023).
func Apply(d Desired, outerKey, innerKey wgtypes.Key) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	if err := applyIface(wg, d.Outer, outerKey); err != nil {
		return err
	}
	if d.Inner != nil {
		if err := applyIface(wg, *d.Inner, innerKey); err != nil {
			return err
		}
	} else if l, err := netlink.LinkByName(Inner); err == nil {
		if err := netlink.LinkDel(l); err != nil {
			return fmt.Errorf("remove %s: %w", Inner, err)
		}
	}
	if d.Forward {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
			return fmt.Errorf("ip forwarding for the relay: %w", err)
		}
	}
	return nil
}

func applyIface(wg *wgctrl.Client, want Iface, priv wgtypes.Key) error {
	link, err := netlink.LinkByName(want.Name)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = want.Name
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}); err != nil {
			return fmt.Errorf("create %s: %w", want.Name, err)
		}
		if link, err = netlink.LinkByName(want.Name); err != nil {
			return err
		}
	}
	cur, err := wg.Device(want.Name)
	if err != nil {
		cur = nil
	}
	cfg, changed, err := Diff(want, priv, cur)
	if err != nil {
		return err
	}
	if changed {
		if err := wg.ConfigureDevice(want.Name, cfg); err != nil {
			return fmt.Errorf("configure %s: %w", want.Name, err)
		}
	}
	addr, err := netlink.ParseAddr(want.Address)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("%s address: %w", want.Name, err)
	}
	if want.MTU > 0 && link.Attrs().MTU != want.MTU {
		if err := netlink.LinkSetMTU(link, want.MTU); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	// Routes: the wanted ones, and none left over from peers that are gone.
	wanted := map[string]bool{}
	for _, r := range want.Routes {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return err
		}
		wanted[n.String()] = true
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: n}); err != nil {
			return fmt.Errorf("route %s via %s: %w", n, want.Name, err)
		}
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.Dst == nil || r.Protocol == netlink.RouteProtocol(2) /* kernel: the address's own */ || wanted[r.Dst.String()] {
			continue
		}
		if slices.Contains([]string{addr.IPNet.String()}, r.Dst.String()) {
			continue
		}
		_ = netlink.RouteDel(&r)
	}
	return nil
}
