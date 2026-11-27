package worker

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/builtin/kri/cloudhypervisor"
)

// IPv6 at the edge (the IPv6 effort) on the host: the bridge has the host's address in its IPv6
// silo /64 (the silos' gateway), the host forwards IPv6 (NAT66 out, DNAT in, as kni's rules say),
// and the IPv6 addresses this host's silos hold (kept IPv6 IPs, IPv6 host addresses) are on its
// uplink as /128s. IPv6 addresses have no labels, so Kevaso's carry an address protocol of its own
// (AddrProto) instead of IPv4's IFACE:kv label; kvoadm reset removes them by it.

// AddrProto is the address protocol Kevaso's IPv6 addresses carry (ip address add … proto).
const AddrProto = "0x6b"

// run6 runs a command on the host and returns what it printed (tests replace it).
var run6 = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// sysctl6 reads and writes /proc/sys (tests replace them).
var (
	readSysctl = func(path string) (string, error) {
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
	writeSysctl = func(path, v string) error { return os.WriteFile(path, []byte(v+"\n"), 0o644) }
)

// ours6 are the IPv6 addresses (with their prefix length) Kevaso put on an interface, read from
// `ip -6 -o addr show dev IFACE`: the lines with its address protocol.
func ours6(out string) map[netip.Addr]int {
	have := map[netip.Addr]int{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		mine := false
		var p netip.Prefix
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "inet6":
				p, _ = netip.ParsePrefix(f[i+1])
			case "proto":
				mine = f[i+1] == AddrProto
			}
		}
		if mine && p.IsValid() {
			have[p.Addr()] = p.Bits()
		}
	}
	return have
}

// syncAddresses6 keeps Kevaso's IPv6 addresses on iface as want says (address → prefix length),
// and removes its others there. nodad: they are the host's to answer for at once (a silo's
// gateway, a held address). deprecated: the host never picks them as the source of its own
// connections (preferred_lft 0); they still receive, and kni sends from them where it SNATs.
func syncAddresses6(ctx context.Context, iface string, want map[netip.Addr]int, deprecated bool) error {
	out, err := run6(ctx, "ip", "-6", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return &cmdError{"ip -6 addr show dev " + iface, err, string(out)}
	}
	have := ours6(string(out))
	for a, bits := range have {
		if w, ok := want[a]; !ok || w != bits {
			_, _ = run6(ctx, "ip", "-6", "addr", "del", netip.PrefixFrom(a, bits).String(), "dev", iface)
			delete(have, a)
		}
	}
	for a, bits := range want {
		if _, ok := have[a]; ok {
			continue
		}
		args := []string{"-6", "addr", "add", netip.PrefixFrom(a, bits).String(), "dev", iface, "proto", AddrProto, "nodad"}
		if deprecated {
			args = append(args, "preferred_lft", "0")
		}
		if b, err := run6(ctx, "ip", args...); err != nil && !strings.Contains(string(b), "File exists") {
			return &cmdError{"ip -6 addr add " + a.String(), err, string(b)}
		}
	}
	return nil
}

// syncBridge6 puts the host's address in its IPv6 silo subnet on the bridge (or takes Kevaso's
// IPv6 addresses off it when the host has none) and, with one, turns IPv6 forwarding on. Forwarding
// on makes Linux ignore router advertisements on an interface whose accept_ra is 1; the uplink's
// own IPv6 address may come from them (SLAAC), so its accept_ra goes to 2 (accept them while
// forwarding) first.
func syncBridge6(ctx context.Context, me *v1.Host, uplink6 string) error {
	want := map[netip.Addr]int{}
	sub6, gw6, ok := SiloNetwork6(me)
	if ok {
		want[gw6] = sub6.Bits()
	}
	if _, err := run6(ctx, "ip", "link", "show", cloudhypervisor.Bridge); err != nil {
		return nil // no bridge (yet): its runtime makes it
	}
	if ok {
		conf := "/proc/sys/net/ipv6/conf/" + cloudhypervisor.Bridge + "/"
		if v, err := readSysctl(conf + "disable_ipv6"); err == nil && v != "0" {
			if err := writeSysctl(conf+"disable_ipv6", "0"); err != nil {
				return err
			}
		}
		if v, err := readSysctl(conf + "accept_ra"); err == nil && v != "0" { // the silos' side: no RA taken from them
			_ = writeSysctl(conf+"accept_ra", "0")
		}
	}
	if err := syncAddresses6(ctx, cloudhypervisor.Bridge, want, false); err != nil {
		return err
	}
	if !ok {
		return nil // forwarding is left as it is: kvoadm reset puts it back
	}
	if safeIfname(uplink6) {
		p := "/proc/sys/net/ipv6/conf/" + uplink6 + "/accept_ra"
		if v, err := readSysctl(p); err == nil && v == "1" {
			if err := writeSysctl(p, "2"); err != nil {
				return err
			}
		}
	}
	const fwd = "/proc/sys/net/ipv6/conf/all/forwarding"
	if v, err := readSysctl(fwd); err != nil || v != "1" {
		return writeSysctl(fwd, "1")
	}
	return nil
}

// safeIfname: an interface name that is safe in a /proc/sys path (1-15 of [A-Za-z0-9_.-], not
// "." or "..").
const ifnameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."

func safeIfname(n string) bool {
	if n == "" || len(n) > 15 || n == "." || n == ".." {
		return false
	}
	for _, c := range []byte(n) {
		if !strings.ContainsRune(ifnameChars, rune(c)) {
			return false
		}
	}
	return true
}

// probe6 is any global IPv6 address: DetectIPv6 asks the kernel which source it would use to
// reach it (a route lookup; nothing is sent).
const probe6 = "2606:4700:4700::1111"

// DetectIPv6 is the host's global IPv6 address: the source the kernel picks towards the IPv6
// internet (so not a deprecated one, as Kevaso's held addresses are). "" when it has no route
// there, or that source isn't a global unicast address (unique local, link-local): IPv4 only.
// Linux only.
func DetectIPv6(ctx context.Context) string {
	if runtime.GOOS != "linux" {
		return ""
	}
	out, err := run6(ctx, "ip", "-6", "-o", "route", "get", probe6)
	if err != nil {
		return ""
	}
	return routeSrc6(string(out))
}

// routeSrc6 reads `ip -6 -o route get`'s source address, when it is one a host may have as its
// external IPv6.
func routeSrc6(out string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "src" {
			if a, ok := hostAddr(f[i+1]); ok && a.Is6() {
				return a.String()
			}
		}
	}
	return ""
}

// split46 splits addresses into the IPv4 ones (as given) and the IPv6 ones (as /128s).
func split46(addrs []string) (v4 []string, v6 map[netip.Addr]int) {
	v6 = map[netip.Addr]int{}
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil:
		case a.Is4():
			if !slices.Contains(v4, s) {
				v4 = append(v4, s)
			}
		default:
			v6[a] = 128
		}
	}
	return v4, v6
}

// uplink6 is the interface the host's IPv6 addresses go on: the one with its external IPv6
// address, else the one with its main address.
func uplink6(me *v1.Host) string {
	if a, ok := hostAddr(me.ExternalIPv6()); ok && a.Is6() {
		if i := uplink(a.String()); i != "" {
			return i
		}
	}
	return uplink(me.Reach())
}
