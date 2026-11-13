// Package ips holds the pure decisions about IP objects (design §7.2c-1): who claims an address,
// who holds it, when it goes, and which of a host's extra addresses the built-in ip-pool class
// hands out. The controller (internal/controllers/ip) and the API server's admission call these;
// nothing here talks to the API.
//
// The life of an IP:
//   - reserved: it has an address and nobody holds it (made by hand, or let go and kept);
//   - bound: one silo or one Service holds it (status.boundTo); naming a bound IP is refused;
//   - let go when its holder is gone or no longer names it: kept (reclaim Retain), or deleted
//     (reclaim Delete);
//   - released only when the IP itself is deleted, which is refused while it's bound.
package ips

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Claim is an object that names an IP (or had one made for it): a would-be holder.
type Claim struct {
	Holder   string // silo/NAME | service/NAME
	UID      string
	Created  time.Time
	Deleting bool   // it still holds what it holds, but never takes anything new
	Host     string // a silo's host ("" while unplaced, or a Service)
}

// Claims are the silos and Services in ip's namespace that name it, or that it was made for (an
// IP made for a service is claimed by that service only while it owns it or is bound to it:
// another silo of the same name never takes a kept one by accident).
func Claims(ip *v1.IP, silos []*v1.Silo, svcs []*v1.Service) []Claim {
	var out []Claim
	ours := func(uid string) bool {
		return ip.Status.BoundUID == uid || slices.ContainsFunc(ip.OwnerReferences, func(r meta.OwnerReference) bool { return r.UID == uid })
	}
	created := func(t *time.Time) time.Time {
		if t == nil {
			return time.Time{}
		}
		return *t
	}
	for _, s := range silos {
		if s.Namespace != ip.Namespace {
			continue
		}
		claims := false
		if n, made := v1.SiloServiceIP(s); n == ip.Name && (!made || ours(s.UID)) {
			claims = true
		}
		if v1.SiloEgressIP(s) == ip.Name && s.Spec.Network.Egress.IP == ip.Name {
			claims = true
		}
		if claims {
			out = append(out, Claim{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID, Created: created(s.CreationTimestamp),
				Deleting: s.DeletionTimestamp != nil, Host: s.Status.Host})
		}
	}
	for _, svc := range svcs {
		if svc.Namespace != ip.Namespace {
			continue
		}
		if n, made := v1.ServiceIP(svc); n == ip.Name && (!made || ours(svc.UID)) {
			out = append(out, Claim{Holder: v1.HolderServicePrefix + svc.Name, UID: svc.UID, Created: created(svc.CreationTimestamp),
				Deleting: svc.DeletionTimestamp != nil})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].Holder < out[j].Holder
	})
	return out
}

// Bind is who holds ip given its claims: its holder while that still claims it (even while being
// deleted: the address is still in use until it's gone), else the oldest claim not being deleted,
// else nobody. One holder at a time; the others wait and are told who holds it.
func Bind(ip *v1.IP, claims []Claim) (Claim, bool) {
	for _, c := range claims {
		if c.UID == ip.Status.BoundUID && ip.Status.BoundUID != "" {
			return c, true
		}
	}
	if ip.DeletionTimestamp != nil {
		return Claim{}, false // being released: nobody new
	}
	for _, c := range claims {
		if !c.Deleting {
			return c, true
		}
	}
	return Claim{}, false
}

// Decision is what becomes of an IP now.
type Decision struct {
	Holder Claim
	Bound  bool
	// Delete: reclaim Delete and nothing holds it any more: the IP goes (and its address with it).
	Delete bool
	Why    string
}

// Decide binds ip and says whether it goes. An IP with reclaim Delete goes when it is let go: its
// owner (the service it was made for) no longer claims it, or, with no owner, a holder it had
// let go of it. A kept IP (Retain) never goes by itself.
func Decide(ip *v1.IP, claims []Claim) Decision {
	h, ok := Bind(ip, claims)
	d := Decision{Holder: h, Bound: ok}
	if ok || ip.Kept() || ip.DeletionTimestamp != nil {
		return d
	}
	owned := false
	for _, r := range ip.OwnerReferences {
		owned = true
		if slices.ContainsFunc(claims, func(c Claim) bool { return c.UID == r.UID }) {
			return d // its owner still claims it (and will hold it)
		}
	}
	switch {
	case owned:
		d.Delete, d.Why = true, "the service it was made for no longer uses it (reclaim Delete)"
	case ip.Status.BoundTo != "":
		d.Delete, d.Why = true, ip.Status.BoundTo+" let it go (reclaim Delete)"
	}
	return d
}

// CanName says why holder (with uid) can't name ip ("" when it can): it's held by someone else.
func CanName(ip *v1.IP, holder, uid string) string {
	if ip.Status.BoundTo == "" || ip.Status.BoundUID == uid || ip.Status.BoundTo == holder {
		return ""
	}
	return fmt.Sprintf("IP %s is held by %s: an IP serves one silo or one Service at a time (delete or change that one first, or name another IP)", ip.Name, ip.Status.BoundTo)
}

// CanDelete says why ip can't be deleted now ("" when it can).
func CanDelete(ip *v1.IP) string {
	if ip.Status.BoundTo == "" {
		return ""
	}
	return fmt.Sprintf("IP %s is held by %s: deleting it would take the address from under it; delete that first, or have it name no IP", ip.Name, ip.Status.BoundTo)
}

// ── ip-pool: a host's own extra addresses ────────────────────────────────────

// Expand lists the usable IPv4 addresses of CIDRs and single addresses, in order (a /31 or /32:
// every address; wider: without the network and broadcast addresses).
func Expand(list []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, a := range list {
		pfx, err := Parse(a)
		if err != nil {
			return nil, err
		}
		if pfx.Bits() >= 31 {
			for x := pfx.Addr(); pfx.Contains(x); x = x.Next() {
				out = append(out, x)
			}
			continue
		}
		last := pfx.Addr()
		for x := pfx.Addr(); pfx.Contains(x); x = x.Next() {
			last = x
		}
		for x := pfx.Addr().Next(); x.Compare(last) < 0; x = x.Next() {
			out = append(out, x)
		}
	}
	return out, nil
}

// MaxRange is the widest range a host can declare (a /22: 1022 addresses).
const MaxRange = 22

// Parse reads one IPv4 CIDR or single address, masked.
func Parse(a string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(a)
	if err != nil {
		addr, aerr := netip.ParseAddr(a)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("%q isn't an address or CIDR", a)
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q: IPv6 comes later; IPv4 for now", a)
	}
	if pfx.Bits() < MaxRange {
		return netip.Prefix{}, fmt.Errorf("%q: at most a /%d per range", a, MaxRange)
	}
	return pfx.Masked(), nil
}

// Overlap says whether two of a host's declared ranges overlap ("" if none do), across all hosts:
// an address is routed to one host.
func Overlap(hosts []*v1.Host) string {
	type r struct {
		host string
		pfx  netip.Prefix
	}
	var all []r
	for _, h := range hosts {
		for _, a := range h.Spec.Network.Addresses {
			if p, err := Parse(a); err == nil {
				all = append(all, r{h.Name, p})
			}
		}
	}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[i].pfx.Overlaps(all[j].pfx) {
				return fmt.Sprintf("%s (on %s) overlaps %s (on %s): an address is routed to one host", all[i].pfx, all[i].host, all[j].pfx, all[j].host)
			}
		}
	}
	return ""
}

// held are the ip-pool addresses IPs other than self hold on host.
func held(host string, all []*v1.IP, self *v1.IP) map[string]string {
	out := map[string]string{}
	for _, x := range all {
		if x.Spec.Class != v1.LBIPPool || x.Status.Host != host || x.Status.Address == "" {
			continue
		}
		if self != nil && x.Namespace == self.Namespace && x.Name == self.Name {
			continue
		}
		out[x.Status.Address] = x.Namespace + "/" + x.Name
	}
	return out
}

// Free counts each host's free ip-pool addresses (self's own not counted as taken).
func Free(hosts []*v1.Host, all []*v1.IP, self *v1.IP) map[string]int {
	out := map[string]int{}
	for _, h := range hosts {
		addrs, err := Expand(h.Spec.Network.Addresses)
		if err != nil {
			continue
		}
		taken := held(h.Name, all, self)
		n := 0
		for _, a := range addrs {
			if taken[a.String()] == "" {
				n++
			}
		}
		out[h.Name] = n
	}
	return out
}

// Allocate picks ip's address from a host's extra addresses: spec.host's, else the host its holder
// is placed on (placed), else the first host (by name) with one free. spec.address picks one. No
// address is ever given twice, and a host's addresses only ever go on that host.
func Allocate(ip *v1.IP, hosts []*v1.Host, all []*v1.IP, placed string) (host, addr string, err error) {
	want := ip.Spec.Host
	if want == "" {
		want = placed
	}
	sorted := slices.Clone(hosts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var tried []string
	for _, h := range sorted {
		if want != "" && h.Name != want {
			continue
		}
		addrs, err := Expand(h.Spec.Network.Addresses)
		if err != nil {
			return "", "", fmt.Errorf("host %s: %w", h.Name, err)
		}
		if len(addrs) == 0 {
			tried = append(tried, h.Name+" has no extra addresses (kvoadm host addresses "+h.Name+" add CIDR)")
			continue
		}
		taken := held(h.Name, all, ip)
		if a := ip.Spec.Address; a != "" {
			if !slices.ContainsFunc(addrs, func(x netip.Addr) bool { return x.String() == a }) {
				tried = append(tried, a+" isn't one of "+h.Name+"'s addresses")
				continue
			}
			if who := taken[a]; who != "" {
				tried = append(tried, a+" on "+h.Name+" is IP "+who+"'s")
				continue
			}
			return h.Name, a, nil
		}
		for _, x := range addrs {
			if taken[x.String()] == "" {
				return h.Name, x.String(), nil
			}
		}
		tried = append(tried, h.Name+" has no free address")
	}
	switch {
	case want != "" && len(tried) == 0:
		return "", "", fmt.Errorf("host %s doesn't exist", want)
	case len(tried) == 0:
		return "", "", fmt.Errorf("no host has extra addresses (kvoadm host addresses HOST add CIDR)")
	}
	return "", "", fmt.Errorf("no address: %s", strings.Join(tried, "; "))
}

// CheckHostAddresses says why host can't have only next as its extra addresses ("" when it can):
// an address an IP holds can't be taken from the host.
func CheckHostAddresses(host string, next []string, all []*v1.IP) string {
	addrs, err := Expand(next)
	if err != nil {
		return err.Error()
	}
	have := map[string]bool{}
	for _, a := range addrs {
		have[a.String()] = true
	}
	var gone []string
	for _, x := range all {
		if x.Spec.Class == v1.LBIPPool && x.Status.Host == host && x.Status.Address != "" && !have[x.Status.Address] {
			gone = append(gone, x.Status.Address+" (IP "+x.Namespace+"/"+x.Name+")")
		}
	}
	if len(gone) == 0 {
		return ""
	}
	sort.Strings(gone)
	return "these addresses are in use, so they stay until their IPs are deleted: " + strings.Join(gone, ", ")
}
