// Package ips holds the pure decisions about IP objects (design §7.2c-1): who claims an address,
// who holds it, when it goes, and which of a host's extra addresses the built-in ip-pool class
// hands out. The controllers (internal/controllers/ip, provider) and the API server's admission
// call these; nothing here talks to the API.
//
// The life of an IP:
//   - reserved: it has an address and nobody holds it (made by hand, or let go and kept);
//   - held: by the services that claim it, each on its own ports (a balancer's address, shared),
//     or by one silo (an address one host has at a time: exclusive). A port two claims want on one
//     address goes to the first; the other waits, told who has it;
//   - let go when its last holder is gone or no longer names it: kept (reclaim Retain), or
//     deleted (reclaim Delete);
//   - released only when the IP itself is deleted, which is refused while anything holds it.
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

// Claim is a silo or Service that names an IP (or whose IP it is by default, or made for it).
type Claim struct {
	Holder   string // silo/NAME | service/NAME
	UID      string
	Created  time.Time
	Deleting bool     // it still holds what it holds, but takes nothing new
	Host     string   // a silo's host ("" while unplaced, or a Service)
	Ports    []string // PORT/PROTO it takes on the address
}

// Claims are the silos and Services in ip's namespace whose service is on ip: those naming it, of
// its class on the namespace's default for the class (its name), and, for one made for a service,
// that service while it owns it or holds it (another of the same name never takes a kept one).
// exclusive: ip's class has an address only one host can have at a time.
func Claims(ip *v1.IP, exclusive bool, silos []*v1.Silo, svcs []*v1.Service) []Claim {
	var out []Claim
	ours := func(uid string) bool {
		return ip.Status.Holds(uid) || slices.ContainsFunc(ip.OwnerReferences, func(r meta.OwnerReference) bool { return r.UID == uid })
	}
	claims := func(class, name string, way v1.IPWay, uid string) bool {
		switch {
		case name != ip.Name || way == v1.IPNone:
			return false
		case way == v1.IPNamed:
			return true
		case class != ip.Spec.Class:
			return false
		case way == v1.IPMade:
			return ours(uid)
		}
		return true // the default one of its class
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
		c := Claim{Holder: v1.HolderSiloPrefix + s.Name, UID: s.UID, Created: created(s.CreationTimestamp), Deleting: s.DeletionTimestamp != nil, Host: s.Status.Host}
		class := ""
		if sv := s.Spec.Service; sv != nil && sv.LoadBalancer != nil {
			class = sv.LoadBalancer.Class
		}
		n, way := v1.SiloServiceIP(s, exclusive)
		switch {
		case claims(class, n, way, s.UID):
			c.Ports = v1.SiloPorts(s)
			out = append(out, c)
		case s.Spec.Network.Egress.IP == ip.Name && v1.SiloEgressIP(s) == ip.Name:
			out = append(out, c) // it only sends from it: no ports in
		}
	}
	for _, svc := range svcs {
		if svc.Namespace != ip.Namespace {
			continue
		}
		if n, way := v1.ServiceIP(svc, exclusive); claims(svc.Spec.LoadBalancerClass, n, way, svc.UID) {
			out = append(out, Claim{Holder: v1.HolderServicePrefix + svc.Name, UID: svc.UID, Created: created(svc.CreationTimestamp),
				Deleting: svc.DeletionTimestamp != nil, Ports: v1.ServicePorts(svc)})
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

// Bind is who holds ip given its claims, and why the others wait. Its holders keep it while they
// still claim it (even while being deleted: the address is in use until they're gone); then the
// oldest claims not being deleted, first come first served. An exclusive address has one holder;
// a shared one has any number, but each port (and protocol) once: a claim wanting a port another
// holder has waits, whole, told who has it.
func Bind(ip *v1.IP, exclusive bool, claims []Claim) (holders []Claim, waiting []v1.IPWaiting) {
	held := map[string]bool{}
	for _, h := range ip.Status.BoundTo {
		held[h.UID] = true
	}
	ordered := make([]Claim, 0, len(claims))
	for _, c := range claims { // current holders first, in their order
		if held[c.UID] {
			ordered = append(ordered, c)
		}
	}
	for _, c := range claims {
		if !held[c.UID] {
			ordered = append(ordered, c)
		}
	}
	taken := map[string]string{} // port → holder
	for _, c := range ordered {
		isHolder := held[c.UID]
		switch {
		case !isHolder && ip.DeletionTimestamp != nil:
			waiting = append(waiting, v1.IPWaiting{Holder: c.Holder, UID: c.UID, Reason: "IP " + ip.Name + " is being released"})
			continue
		case !isHolder && c.Deleting:
			continue
		case exclusive && len(holders) > 0:
			waiting = append(waiting, v1.IPWaiting{Holder: c.Holder, UID: c.UID, Reason: "IP " + ip.Name + " is held by " + holders[0].Holder +
				": its address is one host's at a time, so one silo holds it (name another IP, or leave out ip for one of its own)"})
			continue
		}
		if p, who := clash(c.Ports, taken); p != "" {
			waiting = append(waiting, v1.IPWaiting{Holder: c.Holder, UID: c.UID, Reason: "port " + p + " on IP " + ip.Name + " is " + who + "'s: name another ip, or use another port"})
			continue
		}
		for _, p := range c.Ports {
			taken[p] = c.Holder
		}
		holders = append(holders, c)
	}
	return holders, waiting
}

func clash(ports []string, taken map[string]string) (string, string) {
	for _, p := range ports {
		if who := taken[p]; who != "" {
			return p, who
		}
	}
	return "", ""
}

// Decision is what becomes of an IP now.
type Decision struct {
	Holders []Claim
	Waiting []v1.IPWaiting
	// Delete: reclaim Delete and nothing holds it any more: the IP goes (and its address with it).
	Delete bool
	Why    string
}

// BoundTo is the status list of holders.
func (d Decision) BoundTo() []v1.IPHolder {
	var out []v1.IPHolder
	for _, h := range d.Holders {
		out = append(out, v1.IPHolder{Holder: h.Holder, UID: h.UID, Ports: h.Ports})
	}
	return out
}

// Decide binds ip and says whether it goes. With reclaim Delete it goes once nothing holds it:
// its last holder let go, the service it was made for no longer names it, or (the namespace's
// default for its class) nothing claims it. A kept IP (Retain) never goes by itself.
func Decide(ip *v1.IP, exclusive bool, claims []Claim) Decision {
	h, w := Bind(ip, exclusive, claims)
	d := Decision{Holders: h, Waiting: w}
	if len(h) > 0 || ip.Kept() || ip.DeletionTimestamp != nil {
		return d
	}
	owned := false
	for _, r := range ip.OwnerReferences {
		owned = true
		if slices.ContainsFunc(claims, func(c Claim) bool { return c.UID == r.UID && !c.Deleting }) {
			return d // its owner still claims it (and will hold it)
		}
	}
	switch {
	case owned:
		d.Delete, d.Why = true, "the service it was made for no longer uses it (reclaim Delete)"
	case len(ip.Status.BoundTo) > 0:
		d.Delete, d.Why = true, "its last holder let it go (reclaim Delete)"
	case ip.Labels[v1.LabelDefaultIP] != "" && len(claims) == 0:
		d.Delete, d.Why = true, "no service of class "+ip.Spec.Class+" is on it any more (reclaim Delete)"
	}
	return d
}

// CanName says why a service (holder, uid, on ports) can't be on ip ("" when it can): an exclusive
// address someone else holds, or a port another holder has on it.
func CanName(ip *v1.IP, exclusive bool, holder, uid string, ports []string) string {
	taken := map[string]string{}
	for _, h := range ip.Status.BoundTo {
		if h.UID == uid || h.Holder == holder {
			continue
		}
		if exclusive {
			return fmt.Sprintf("IP %s is held by %s: its address is one host's at a time, so one silo holds it (delete or change that one first, or name another IP)", ip.Name, h.Holder)
		}
		for _, p := range h.Ports {
			taken[p] = h.Holder
		}
	}
	if p, who := clash(ports, taken); p != "" {
		return fmt.Sprintf("port %s on IP %s is %s's: name another ip (or set loadBalancer.dedicated), or use another port", p, ip.Name, who)
	}
	return ""
}

// CanDelete says why ip can't be deleted now ("" when it can).
func CanDelete(ip *v1.IP) string {
	if len(ip.Status.BoundTo) == 0 {
		return ""
	}
	return fmt.Sprintf("IP %s is held by %s: deleting it would take the address from under them; delete those first, or have them name no IP", ip.Name, ip.Status.Holders())
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
