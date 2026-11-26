package scheduler

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
	"kevaso.com/core/internal/plugins"
	"kevaso.com/core/sdk/kplugin"
)

// Placement follows the address (networking v2, "Rules"). Each way in a silo has sets where the
// silo can be:
//   - hostPort worker: anywhere (the address is the worker's, and changes with it);
//   - hostPort ip, loadBalancer ip, egress.source ip: the IP's; an IP of type Host is pinned to the
//     host with its address, an IP of type Provider is within its provider's reach (Reach: its
//     region, and only its own machines when it says so);
//   - own (a SiloSet instance's IPSet member, by ordinal): the same, by the member's type;
//   - a load balancer: within its provider's reach.
//
// Several ways in intersect. What could work later (an IP not held yet, held by another silo, no
// free IPSet member, a Provider IP with no address yet, a provider not installed yet) leaves the
// silo unschedulable with that reason, for the whole silo, and it goes ahead by itself once that
// changes: nothing here refuses. What admission lets through but no host can ever meet (two
// addresses no host has together) is unschedulable too, with both reasons.

// Reacher answers where a provider's IPs and balancers reach silos (plugins.Networking does).
type Reacher interface {
	Reach(provider string) (plugins.Reach, error)
}

// limit is one way in's rule on where the silo can be. Each set field narrows it; its why is what
// a host failing it is told.
type limit struct {
	host, hostWhy         string   // only this host
	provider, providerWhy string   // only this provider's machines
	regions               []string // only these regions (the provider's, on its machines); empty: any
	regionProvider        string   // whose region a host is judged by (its own machines' region)
	regionWhy             string
	because               string // the rule, for people ("IP mail is host bm-1's address")
	subject               string // the way in, for people ("IP mail", "service shop's balancer")
	pinned                string // with host: why, short ("IP mail is that host's address")
}

// excludes is why h is outside l ("" when it's inside).
func (l limit) excludes(h *v1.Host) string {
	if l.host != "" && h.Name != l.host {
		return l.hostWhy
	}
	if l.provider != "" && (h.Status.Provider == nil || h.Status.Provider.Name != l.provider) {
		return l.providerWhy
	}
	if len(l.regions) > 0 && !slices.Contains(l.regions, hostRegion(h, l.regionProvider)) {
		return l.regionWhy
	}
	return ""
}

// hostRegion is h's region as provider sees it: its provider's region on one of provider's
// machines, its spec.region otherwise.
func hostRegion(h *v1.Host, provider string) string {
	if p := h.Status.Provider; p != nil && provider != "" && p.Name == provider && p.Region != "" {
		return p.Region
	}
	if p := h.Status.Provider; p != nil && h.Spec.Region == "" {
		return p.Region
	}
	return h.Spec.Region
}

// reach is env's answer for provider; without a Networking, the old rule: only the provider's
// machines, in the region.
func (env Env) reach(provider string) (plugins.Reach, error) {
	if env.Networking == nil {
		return plugins.Reach{Scope: kplugin.FollowsRegion, OwnHostsOnly: true}, nil
	}
	return env.Networking.Reach(provider)
}

// Area is where a silo's ways in let it be: the intersection of their rules.
type Area struct {
	Host     string   // only this host ("": any)
	Provider string   // only this provider's machines ("": any)
	Regions  []string // only these regions (nil: any)
	Because  []string // each rule, for people
	Subjects []string // the ways in that limit it ("IP mail", "service shop's balancer")
	PinnedBy string   // with Host: why, short ("IP mail is that host's address")
	// Conflict: no host can meet them all (why), though each could alone.
	Conflict string
}

// Anywhere says whether nothing limits it.
func (a Area) Anywhere() bool {
	return a.Host == "" && a.Provider == "" && a.Regions == nil && a.Conflict == ""
}

// String is the area for people: anywhere, host bm-1, linode machines in us-ord, region us-ord.
func (a Area) String() string {
	switch {
	case a.Conflict != "":
		return "nowhere"
	case a.Host != "":
		return "host " + a.Host
	case a.Anywhere():
		return "anywhere"
	}
	var s string
	if a.Provider != "" {
		s = a.Provider + " machines"
	}
	if a.Regions != nil {
		in := "region"
		if len(a.Regions) > 1 {
			in = "regions"
		}
		if s == "" {
			s = in + " " + strings.Join(a.Regions, ", ")
		} else {
			s += " in " + strings.Join(a.Regions, ", ")
		}
	}
	return s
}

// addressLimits are the rules the silo's ways in set (one per way in that sets any), or the
// reason it can't be placed anywhere yet. Hosts are env.Hosts (named host addresses).
func addressLimits(s *v1.Silo, env Env) ([]limit, string) {
	var out []limit
	for _, n := range s.Spec.NamedIPs() {
		x, wait := heldOrWhy(s, n.Name, "IP "+n.Name, env)
		if wait != "" {
			return nil, wait
		}
		l, wait := ipLimit(x, "IP "+n.Name, env)
		if wait != "" {
			return nil, wait
		}
		out = append(out, l)
	}
	if s.Spec.UsesOwn() {
		l, wait := ownLimit(s, env)
		if wait != "" {
			return nil, wait
		}
		out = append(out, l)
	}
	for _, sv := range s.Spec.Balancers() {
		if sv.LoadBalancer == nil || sv.LoadBalancer.IP != "" || sv.LoadBalancer.Provider == "" {
			continue // a kept IP in front is the IP's rule, above
		}
		l, wait := balancerLimit(s, sv, env)
		if wait != "" {
			return nil, wait
		}
		out = append(out, l)
	}
	return out, ""
}

// heldOrWhy is the IP named name if s holds it, or why s can't have it yet. what names it for
// people ("IP mail", "IP edge-0 (IPSet edge, member 0)").
func heldOrWhy(s *v1.Silo, name, what string, env Env) (*v1.IP, string) {
	x := findIP(env, s.Namespace, name)
	switch {
	case x == nil:
		return nil, what + " doesn't exist"
	case x.Status.Holds(s.UID):
		return x, ""
	}
	if why := x.Status.WaitingReason(s.UID); why != "" {
		return nil, why
	}
	if h := x.Status.Holder; h != nil {
		return nil, what + " is held by " + h.Holder + ": one holder at a time; it's this silo's once that one lets it go"
	}
	return nil, "waiting for " + what + " to be bound to it"
}

// ipLimit is where IP x's address can be (what names it), or why it can't be anywhere yet.
func ipLimit(x *v1.IP, what string, env Env) (limit, string) {
	switch x.Spec.Type {
	case v1.IPTypeHost:
		where := x.Status.Host
		if where == "" {
			if hh, _, ok := ips.FindAddress(env.Hosts, x.Spec.HostAddress); ok {
				where = hh.Name
			}
		}
		if where == "" {
			return limit{}, noHostAddress(x.Spec.HostAddress)
		}
		why := what + " is host " + where + "'s address"
		return limit{host: where, hostWhy: why, because: why, subject: what, pinned: what + " is that host's address"}, ""
	case v1.IPTypeProvider:
		p, region := x.Spec.Provider, x.Spec.Region
		if x.Status.Region != "" {
			region = x.Status.Region
		}
		r, err := env.reach(p)
		if err != nil {
			return limit{}, what + ": " + err.Error()
		}
		if x.Status.Address == "" {
			why := "waiting for provider " + p + " to reserve " + what + "'s address"
			if c := meta.FindCondition(x.Status.Conditions, "Reserved"); c != nil && c.Status == meta.ConditionFalse && c.Message != "" {
				why += ": " + c.Message
			}
			return limit{}, why
		}
		why := what + " is " + p + "'s, in " + region
		l := limit{because: why, subject: what}
		if r.OwnHostsOnly {
			l.provider, l.providerWhy = p, why
		}
		switch r.Scope {
		case kplugin.FollowsHost:
			if x.Status.Host != "" {
				l.host = x.Status.Host
				l.hostWhy = what + " stays on host " + x.Status.Host + " (provider " + p + "'s addresses don't move)"
				l.because, l.pinned = l.hostWhy, what+" stays on that host"
			}
			fallthrough
		case kplugin.FollowsRegion, "":
			if region != "" {
				l.regions, l.regionProvider, l.regionWhy = []string{region}, p, why
			}
		}
		return l, ""
	}
	return limit{}, what + " has type " + strconv.Quote(x.Spec.Type) + ", which places nothing"
}

func noHostAddress(name string) string {
	return "no host has address " + name + " (kvoadm host addresses HOST add " + name + " ADDRESS)"
}

// balancerLimit is where service sv's balancer reaches silos, or why it can't yet.
func balancerLimit(s *v1.Silo, sv v1.SiloService, env Env) (limit, string) {
	name, p := v1.ServiceNameOf(sv, s.Name), sv.LoadBalancer.Provider
	r, err := env.reach(p)
	if err != nil {
		return limit{}, "service " + name + ": " + err.Error()
	}
	l := limit{subject: "service " + name + "'s balancer"}
	var because []string
	if r.OwnHostsOnly {
		l.provider = p
		l.providerWhy = "service " + name + ": provider " + p + "'s balancer needs a " + p + " machine"
		because = append(because, p+" machines")
	}
	if len(r.Regions) > 0 {
		l.regions, l.regionProvider = slices.Clone(r.Regions), p
		l.regionWhy = "service " + name + ": provider " + p + "'s balancers serve " + strings.Join(r.Regions, ", ")
	}
	// A balancer that exists is where the silo was: it reaches the silo within its scope there.
	if cur := findHost(env.Hosts, s.Status.Host); cur != nil && s.Status.Service.LoadBalancerIP != "" {
		switch r.Scope {
		case kplugin.FollowsHost:
			l.host = cur.Name
			l.hostWhy = "service " + name + ": provider " + p + "'s balancer reaches host " + cur.Name + " only"
			l.pinned = "service " + name + "'s balancer reaches that host only"
		case kplugin.FollowsRegion, "":
			if reg := hostRegion(cur, p); reg != "" {
				l.regions, l.regionProvider = []string{reg}, p
				l.regionWhy = "service " + name + ": provider " + p + "'s balancer is in region " + reg
			}
		}
	}
	if l.regions != nil {
		because = append(because, "in "+strings.Join(l.regions, ", "))
	}
	l.because = "service " + name + ": provider " + p + "'s balancer"
	if len(because) > 0 {
		l.because += " reaches " + strings.Join(because, " ")
	}
	return l, ""
}

func findHost(hosts []*v1.Host, name string) *v1.Host {
	if name == "" {
		return nil
	}
	for _, h := range hosts {
		if h.Name == name {
			return h
		}
	}
	return nil
}

// ownMember is the instance's IPSet member: its IP's name, or (a Static member that's a host
// address with no IP object yet) the host address; what names it for people. wait: why it has
// none yet.
func ownMember(s *v1.Silo, env Env) (ip, hostAddress, what, wait string) {
	set := s.Labels[v1.LabelSiloSet]
	i := v1.InstanceIndex(set, s.Name)
	if set == "" || i < 0 {
		return "", "", "", "own: " + s.Name + " isn't a SiloSet instance, so it has no IPSet member"
	}
	var ss *v1.SiloSet
	for _, x := range env.SiloSets {
		if x.Namespace == s.Namespace && x.Name == set {
			ss = x
		}
	}
	if ss == nil {
		// No SiloSet to read: the member already bound to the instance, if there is one.
		for _, x := range env.IPs {
			if x.Namespace == s.Namespace && x.Labels[v1.LabelIPSetOrdinal] == strconv.Itoa(i) && x.Labels[v1.LabelIPSet] != "" && x.Status.Holds(s.UID) {
				return x.Name, "", fmt.Sprintf("IP %s (IPSet %s, member %d)", x.Name, x.Labels[v1.LabelIPSet], i), ""
			}
		}
		return "", "", "", "waiting for SiloSet " + set + " (own takes its IPSet's member " + strconv.Itoa(i) + ")"
	}
	name := ss.Spec.IPs
	if name == "" {
		return "", "", "", "own: SiloSet " + set + " names no IPSet (spec.ips)"
	}
	var ipset *v1.IPSet
	for _, x := range env.IPSets {
		if x.Namespace == s.Namespace && x.Name == name {
			ipset = x
		}
	}
	if ipset == nil {
		return "", "", "", "IPSet " + name + " doesn't exist"
	}
	member := func(ip string) string { return fmt.Sprintf("IP %s (IPSet %s, member %d)", ip, name, i) }
	for _, m := range ipset.Status.Members {
		if m.Ordinal == i && m.IP != "" {
			return m.IP, "", member(m.IP), ""
		}
	}
	for _, x := range env.IPs {
		if x.Namespace == s.Namespace && x.Labels[v1.LabelIPSet] == name && x.Labels[v1.LabelIPSetOrdinal] == strconv.Itoa(i) {
			return x.Name, "", member(x.Name), ""
		}
	}
	switch ipset.Spec.Type {
	case v1.IPSetStatic:
		if i >= len(ipset.Spec.Members) {
			return "", "", "", fmt.Sprintf("no free member in IPSet %s: instance %s takes member %d, and it has %d (add one at the end)", name, s.Name, i, len(ipset.Spec.Members))
		}
		m := ipset.Spec.Members[i]
		if m.IP != "" {
			return m.IP, "", member(m.IP), ""
		}
		return "", m.HostAddress, fmt.Sprintf("host address %s (IPSet %s, member %d)", m.HostAddress, name, i), ""
	case v1.IPSetDynamic:
		if ipset.Spec.Max > 0 && i >= ipset.Spec.Max {
			return "", "", "", fmt.Sprintf("no free member in IPSet %s: instance %s takes member %d, and its max is %d", name, s.Name, i, ipset.Spec.Max)
		}
		ip := v1.InstanceName(name, i)
		if findIP(env, s.Namespace, ip) == nil {
			return "", "", "", fmt.Sprintf("waiting for IPSet %s to reserve member %d (IP %s)", name, i, ip)
		}
		return ip, "", member(ip), ""
	}
	return "", "", "", "IPSet " + name + " has type " + strconv.Quote(ipset.Spec.Type)
}

// ownLimit is where the instance's IPSet member lets it be.
func ownLimit(s *v1.Silo, env Env) (limit, string) {
	ip, addr, what, wait := ownMember(s, env)
	if wait != "" {
		return limit{}, wait
	}
	if ip == "" {
		h, _, ok := ips.FindAddress(env.Hosts, addr)
		if !ok {
			return limit{}, noHostAddress(addr)
		}
		why := what + " is host " + h.Name + "'s"
		return limit{host: h.Name, hostWhy: why, because: why, subject: what, pinned: what + " is that host's"}, ""
	}
	x, wait := heldOrWhy(s, ip, what, env)
	if wait != "" {
		return limit{}, wait
	}
	return ipLimit(x, what, env)
}

// OwnIP is the instance's IPSet member IP it holds (nil: none, or not held yet).
func OwnIP(s *v1.Silo, env Env) *v1.IP {
	if !s.Spec.UsesOwn() {
		return nil
	}
	ip, _, _, wait := ownMember(s, env)
	if wait != "" || ip == "" {
		return nil
	}
	return heldIP(s, ip, env)
}

// AreaOf is where the silo's ways in let it be, or why it can't be anywhere yet (wait).
func AreaOf(s *v1.Silo, env Env) (a Area, wait string) {
	ls, wait := addressLimits(s, env)
	if wait != "" {
		return Area{}, wait
	}
	return intersect(ls, env.Hosts), ""
}

// intersect is the area every limit allows, with a conflict when none can be met together.
func intersect(ls []limit, hosts []*v1.Host) Area {
	var a Area
	var hostBy, providerBy, regionBy string
	for _, l := range ls {
		a.Because = append(a.Because, l.because)
		if l.subject != "" && !slices.Contains(a.Subjects, l.subject) {
			a.Subjects = append(a.Subjects, l.subject)
		}
		if l.host != "" {
			if a.Host != "" && a.Host != l.host {
				a.Conflict = hostBy + ", and " + l.hostWhy + ": no host has both"
				return a
			}
			a.Host, hostBy, a.PinnedBy = l.host, l.hostWhy, l.pinned
		}
		if l.provider != "" {
			if a.Provider != "" && a.Provider != l.provider {
				a.Conflict = providerBy + ", and " + l.providerWhy + ": no machine is both"
				return a
			}
			a.Provider, providerBy = l.provider, l.providerWhy
		}
		if len(l.regions) > 0 {
			if a.Regions == nil {
				a.Regions, regionBy = slices.Clone(l.regions), l.regionWhy
				continue
			}
			var both []string
			for _, r := range a.Regions {
				if slices.Contains(l.regions, r) {
					both = append(both, r)
				}
			}
			if len(both) == 0 {
				a.Conflict = regionBy + ", and " + l.regionWhy + ": no region is both"
				return a
			}
			a.Regions = both
		}
	}
	// Pinned to a host: it must meet the other rules too.
	if h := findHost(hosts, a.Host); h != nil {
		for _, l := range ls {
			if why := l.excludes(h); why != "" {
				a.Conflict = hostBy + ", and " + why
				return a
			}
		}
	}
	return a
}

// excludedBy is the first limit h is outside of ("" when it's inside them all).
func excludedBy(ls []limit, h *v1.Host) string {
	for _, l := range ls {
		if why := l.excludes(h); why != "" {
			return why
		}
	}
	return ""
}
