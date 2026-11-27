// Package ips holds the pure decisions about IP objects (networking v2): who claims an address,
// who holds it, and a host's named extra addresses. The controllers (internal/controllers/ip,
// provider) and the API server's admission call these; nothing here talks to the API.
//
// The life of an IP:
//   - reserved: it has an address and nobody holds it (made by hand, or let go: it is kept);
//   - held: by one silo or Service at a time, the oldest that names it. The others wait, told
//     who has it, and get it when it is let go;
//   - let go when its holder is gone or no longer names it. Deleting the silo keeps the IP: the
//     next silo naming it gets the same address;
//   - released only when the IP itself is deleted, which is refused while anything holds it.
package ips

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	v1 "kevaso.com/core/api/v1"
)

// Claim is a silo or Service that names an IP.
type Claim struct {
	Holder   string // silo/NAME | service/NAME
	UID      string
	Created  time.Time
	Deleting bool     // it still holds what it holds, but takes nothing new
	Host     string   // a silo's host ("" while unplaced, or a Service)
	Ports    []string // PORT/PROTO it takes on the address
}

// Claims are the silos and Services in ip's namespace that name ip (a service's hostPort.ip or
// loadBalancer.ip, egress.source.ip; a Service's loadBalancer.ip), and the SiloSet instances
// whose own is ip (own resolves an instance's own IP, OwnIP; nil: none), oldest first.
func Claims(ip *v1.IP, silos []*v1.Silo, svcs []*v1.Service, own func(*v1.Silo) string) []Claim {
	var out []Claim
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
		named, owned := slices.Contains(v1.SiloIPs(s), ip.Name), own != nil && own(s) == ip.Name
		if !named && !owned {
			continue
		}
		ports := v1.SiloPortsOn(s, ip.Name)
		if owned {
			ports = append(ports, ownPorts(s)...)
		}
		out = append(out, Claim{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID, Created: created(s.CreationTimestamp),
			Deleting: s.DeletionTimestamp != nil, Host: s.Status.Host, Ports: ports})
	}
	for _, svc := range svcs {
		if svc.Namespace != ip.Namespace || svc.Spec.LoadBalancerIP() != ip.Name {
			continue
		}
		out = append(out, Claim{Holder: v1.HolderServicePrefix + svc.Name, UID: svc.UID, Created: created(svc.CreationTimestamp),
			Deleting: svc.DeletionTimestamp != nil, Ports: v1.ServicePorts(svc)})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].Holder < out[j].Holder
	})
	return out
}

// ownPorts are the ports a silo's hostPort: { own: true } services take on its own IP (PORT/PROTO).
func ownPorts(s *v1.Silo) []string {
	var out []string
	for _, p := range s.Spec.Open() {
		if p.Type == v1.ServiceHostPort && p.Way.Own {
			if k := fmt.Sprintf("%d/%s", p.HostNumber(), p.Protocol); !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
	}
	return out
}

// Bind is who holds ip given its claims, and why the others wait. Its holder keeps it while it
// still claims it (even while being deleted: the address is in use until it's gone); otherwise
// the oldest claim not being deleted takes it. One holder at a time.
func Bind(ip *v1.IP, claims []Claim) (holder *Claim, waiting []v1.IPWaiting) {
	for i, c := range claims {
		if ip.Status.Holds(c.UID) {
			holder = &claims[i]
		}
	}
	for i, c := range claims {
		switch {
		case holder != nil && holder.UID == c.UID:
			continue
		case ip.DeletionTimestamp != nil:
			waiting = append(waiting, v1.IPWaiting{Holder: c.Holder, UID: c.UID, Reason: "IP " + ip.Name + " is being released"})
		case c.Deleting:
		case holder == nil:
			holder = &claims[i]
		default:
			waiting = append(waiting, v1.IPWaiting{Holder: c.Holder, UID: c.UID,
				Reason: "IP " + ip.Name + " is held by " + holder.Holder + ": one holder at a time; it's yours once that one lets it go"})
		}
	}
	return holder, waiting
}

// Decision is what becomes of an IP now.
type Decision struct {
	Holder  *Claim
	Waiting []v1.IPWaiting
}

// StatusHolder is the status's holder (nil: nobody).
func (d Decision) StatusHolder() *v1.IPHolder {
	if d.Holder == nil {
		return nil
	}
	return &v1.IPHolder{Holder: d.Holder.Holder, UID: d.Holder.UID, Ports: d.Holder.Ports}
}

// Decide binds ip. An IP never goes by itself: it is kept until it is deleted.
func Decide(ip *v1.IP, claims []Claim) Decision {
	h, w := Bind(ip, claims)
	return Decision{Holder: h, Waiting: w}
}

// CanDelete says why ip can't be deleted now ("" when it can).
func CanDelete(ip *v1.IP) string {
	if ip.Status.Holder == nil {
		return ""
	}
	return fmt.Sprintf("IP %s is held by %s: deleting it would take the address from under it; delete that one first, or have it name no IP", ip.Name, ip.Status.Holders())
}

// ── A host's named extra addresses ───────────────────────────────────────────

// FindAddress is the host with the extra address named name, and the address (ok false: no host
// has one of that name).
func FindAddress(hosts []*v1.Host, name string) (*v1.Host, v1.HostAddress, bool) {
	for _, h := range hosts {
		if a, ok := h.Address(name); ok {
			return h, a, true
		}
	}
	return nil, v1.HostAddress{}, false
}

// Duplicates says what two hosts' extra addresses share ("" if nothing): a name is unique in the
// cluster, and an address is on one host, never a host's main IP.
func Duplicates(hosts []*v1.Host) string {
	sorted := slices.Clone(hosts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	names := map[string]string{}
	addrs := map[string]string{}
	for _, h := range sorted {
		for _, a := range []string{h.Spec.ExternalIP, h.Spec.InternalIP, h.Spec.ExternalIPv6} {
			if a != "" {
				addrs[a] = h.Name + "'s main IP"
			}
		}
	}
	for _, h := range sorted {
		for _, a := range h.Spec.Addresses {
			if who, ok := names[a.Name]; ok && who != h.Name {
				return fmt.Sprintf("address name %s is %s's already: names are unique in the cluster, pick another", a.Name, who)
			}
			names[a.Name] = h.Name
			if who, ok := addrs[a.Address]; ok && who != h.Name+" ("+a.Name+")" {
				return fmt.Sprintf("address %s (%s on %s) is %s already: an address is on one host", a.Address, a.Name, h.Name, who)
			}
			addrs[a.Address] = h.Name + " (" + a.Name + ")"
		}
	}
	return ""
}

// CheckHostAddresses says why host can't have next as its extra addresses ("" when it can): an
// address an IP of type Host holds stays, by name and address, until that IP is deleted.
func CheckHostAddresses(host string, next []v1.HostAddress, all []*v1.IP) string {
	var gone []string
	for _, x := range all {
		if x.Spec.Type != v1.IPTypeHost || x.Status.Host != host || x.Status.Address == "" {
			continue
		}
		i := slices.IndexFunc(next, func(a v1.HostAddress) bool { return a.Name == x.Spec.HostAddress })
		if i < 0 || next[i].Address != x.Status.Address {
			gone = append(gone, x.Spec.HostAddress+" "+x.Status.Address+" (IP "+x.Namespace+"/"+x.Name+")")
		}
	}
	if len(gone) == 0 {
		return ""
	}
	sort.Strings(gone)
	return "these addresses are reserved, so they stay as they are until their IPs are deleted: " + strings.Join(gone, ", ")
}

// Together says why a silo can't have the Host IPs it names all at once ("" when it can): each
// is pinned to the host with its address, so they must all be one host's. IPs not of type Host,
// and addresses no host has yet, are left out (they could work later).
func Together(named []*v1.IP, hosts []*v1.Host) string {
	first, firstIP := "", ""
	for _, x := range named {
		if x == nil || x.Spec.Type != v1.IPTypeHost {
			continue
		}
		h, _, ok := FindAddress(hosts, x.Spec.HostAddress)
		if !ok {
			continue
		}
		if first == "" {
			first, firstIP = h.Name, x.Name
			continue
		}
		if h.Name != first {
			return fmt.Sprintf("IP %s is on host %s and IP %s on host %s: no host has both, so the silo could never run; name IPs of one host (or a Provider IP)", firstIP, first, x.Name, h.Name)
		}
	}
	return ""
}

// ParseAddress reads one address, IPv4 or IPv6 (no range: an IP is one address). An IPv6 one
// is a unicast address of its own: not loopback, link-local, multicast or unspecified, not the
// IPv4-mapped form (write the IPv4 address), and without a zone.
func ParseAddress(a string) (netip.Addr, error) {
	ad, err := netip.ParseAddr(a)
	if err != nil {
		if _, perr := netip.ParsePrefix(a); perr == nil {
			return netip.Addr{}, fmt.Errorf("%q is a range: one address per name (add each with its own name)", a)
		}
		return netip.Addr{}, fmt.Errorf("%q isn't an address", a)
	}
	switch {
	case ad.Is4():
	case ad.Is4In6():
		return netip.Addr{}, fmt.Errorf("%q is an IPv4-mapped IPv6 address: write the IPv4 address (%s)", a, ad.Unmap())
	case ad.Zone() != "":
		return netip.Addr{}, fmt.Errorf("%q has a zone: write the address alone (a link-local address can't be one of a host's addresses)", a)
	case !ad.IsGlobalUnicast():
		return netip.Addr{}, fmt.Errorf("%q isn't a unicast address of the host's own (loopback, link-local, multicast and :: can't be)", a)
	}
	return ad, nil
}

// ── Families: one IP, one family ─────────────────────────────────────────────

// FamilyMismatch says why a Host IP's family isn't its host address's ("" when it is, or no host
// has that address yet): the fix is the family, or another address.
func FamilyMismatch(x *v1.IP, hosts []*v1.Host) string {
	if x.Spec.Type != v1.IPTypeHost || !knownFamily(x.Spec.Family) {
		return "" // a family that isn't one is refused on its own (admission's checkIP)
	}
	h, a, ok := FindAddress(hosts, x.Spec.HostAddress)
	if !ok || a.Family() == "" || a.Family() == x.Spec.FamilyOrDefault() {
		return ""
	}
	return fmt.Sprintf("host address %s is %s (%s on %s) and the IP is %s: a Host IP's family is its address's; set family: %s, or name an %s address",
		a.Name, a.Family(), a.Address, h.Name, familyWord(x.Spec.Family), a.Family(), x.Spec.FamilyOrDefault())
}

func knownFamily(f string) bool { return f == "" || f == v1.FamilyIPv4 || f == v1.FamilyIPv6 }

// familyWord is a spec's family for people ("IPv4 (the default)" when it says none).
func familyWord(f string) string {
	if f == "" {
		return v1.FamilyIPv4 + " (the default)"
	}
	return f
}

// AddressFamilyConflicts says why host can't have its extra addresses as they are ("" when it
// can): an IP of type Host naming one of them is of the other family.
func AddressFamilyConflicts(h *v1.Host, all []*v1.IP) string {
	var bad []string
	for _, x := range all {
		if x.Spec.Type != v1.IPTypeHost || !knownFamily(x.Spec.Family) {
			continue
		}
		a, ok := h.Address(x.Spec.HostAddress)
		if !ok || a.Family() == "" || a.Family() == x.Spec.FamilyOrDefault() {
			continue
		}
		bad = append(bad, fmt.Sprintf("%s %s is %s and IP %s/%s naming it is %s", a.Name, a.Address, a.Family(), x.Namespace, x.Name, x.Spec.FamilyOrDefault()))
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	return "an IP of type Host is one family, its address's: " + strings.Join(bad, "; ") + ": give the address one of the IP's family, or make an IP of the address's family (an IP's family can't change)"
}

// MemberFamily is the family of a Static set's member, as far as it is known ("" if not yet:
// an IP not made, an address no host has).
func MemberFamily(m v1.IPSetMember, nsIPs []*v1.IP, hosts []*v1.Host) string {
	if m.IP != "" {
		for _, x := range nsIPs {
			if x.Name == m.IP {
				return x.Spec.FamilyOrDefault()
			}
		}
		return ""
	}
	if _, a, ok := FindAddress(hosts, m.HostAddress); ok {
		return a.Family()
	}
	return ""
}

// SetFamilies says why a Static set's members aren't one family ("" when they are, as far as is
// known). nsIPs are the IPs of the set's namespace.
func SetFamilies(set *v1.IPSet, nsIPs []*v1.IP, hosts []*v1.Host) string {
	if set.Spec.Type != v1.IPSetStatic {
		return ""
	}
	first, fi := "", -1
	for i, m := range set.Spec.Members {
		f := MemberFamily(m, nsIPs, hosts)
		if f == "" {
			continue
		}
		if first == "" {
			first, fi = f, i
			continue
		}
		if f != first {
			return fmt.Sprintf("members[%d] (%s) is %s and members[%d] (%s) is %s: a set is one family; make two sets, one per family, and a service on each (a port may be in several services)",
				fi, set.Spec.Members[fi], first, i, m, f)
		}
	}
	return ""
}
