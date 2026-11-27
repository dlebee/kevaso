package apiserver

import (
	"fmt"
	"slices"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/ips"
)

// Admission of networking v2's addresses, pure: what can never work is refused with the fix.
// What could work later (no free set member, an IP held by another silo, provider quota, no
// worker with an external IP) is the scheduler's and the controllers': unschedulable, with the
// reason, until it can.

// ownedBySet says whether a silo is a SiloSet's instance (own is its set's IPSet member).
func ownedBySet(s *v1.Silo) bool {
	return slices.ContainsFunc(s.OwnerReferences, func(r meta.OwnerReference) bool { return r.Kind == "SiloSet" && r.Controller })
}

// checkService is a standalone Service's way in: Internal or LoadBalancer (a group has no one
// worker for a HostPort to arrive at).
func checkService(o *v1.Service) []string {
	var errs []string
	t := o.Spec.TypeOrDefault()
	switch t {
	case v1.ServiceInternal, v1.ServiceLoadBalancer:
	case v1.ServiceHostPort:
		return []string{"type HostPort arrives at the worker running one silo, so a Service of several can't be one: put a HostPort service in each silo's services (or the SiloSet's template, with own: true for an address each), or use type LoadBalancer for the group"}
	default:
		return []string{fmt.Sprintf("type %q: Internal (the default: a virtual IP on the mesh) or LoadBalancer (a provider's balancer in front)", o.Spec.Type)}
	}
	switch l := o.Spec.LoadBalancer; {
	case t == v1.ServiceLoadBalancer && (l == nil || l.Provider == ""):
		errs = append(errs, "type LoadBalancer needs loadBalancer.provider: the installed provider making the balancer (e.g. linode)")
	case t != v1.ServiceLoadBalancer && l != nil:
		errs = append(errs, "loadBalancer goes with type: LoadBalancer")
	case l != nil && !label.MatchString(l.Provider):
		errs = append(errs, fmt.Sprintf("loadBalancer.provider %q: an installed provider's name (e.g. linode)", l.Provider))
	case l != nil && l.IP != "" && !label.MatchString(l.IP):
		errs = append(errs, fmt.Sprintf("loadBalancer.ip %q: an IP's name in this namespace (no kind/ prefix)", l.IP))
	}
	return errs
}

// checkIP: an explicit type, and only the fields it takes.
func checkIP(o *v1.IP) []string {
	sp := o.Spec
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	switch sp.Type {
	case v1.IPTypeHost:
		if sp.HostAddress == "" {
			add("type Host needs hostAddress: the name of one of a host's extra addresses (kvoadm host addresses HOST add NAME ADDRESS)")
		} else if !label.MatchString(sp.HostAddress) {
			add("spec.hostAddress %q: a host address's name (lower-case letters, digits, -)", sp.HostAddress)
		}
		if sp.Provider != "" || sp.Region != "" {
			add("type Host is a host's address: provider and region are for type Provider (drop them, or make it type: Provider)")
		}
	case v1.IPTypeProvider:
		if sp.Provider == "" || sp.Region == "" {
			add("type Provider needs provider and region: the installed provider (e.g. linode) and where to reserve it (e.g. us-ord); never guessed")
		}
		if sp.Provider != "" && !label.MatchString(sp.Provider) {
			add("spec.provider %q: an installed provider's name (e.g. linode)", sp.Provider)
		}
		if sp.HostAddress != "" {
			add("type Provider is reserved from the provider: hostAddress is for type Host (drop it, or make it type: Host)")
		}
	case "":
		add("spec.type is required: Host (one of a host's extra addresses: hostAddress) or Provider (reserved from a provider: provider, region)")
	default:
		add("spec.type %q: Host or Provider", sp.Type)
	}
	if f := checkFamily("spec.family", sp.Family); f != "" {
		add("%s", f)
	}
	return errs
}

// checkFamily is why family isn't one ("" when it is, or empty: IPv4).
func checkFamily(field, family string) string {
	switch family {
	case "", v1.FamilyIPv4, v1.FamilyIPv6:
		return ""
	}
	return fmt.Sprintf("%s %q: IPv4 (the default) or IPv6; one IP is one address of one family (two families on a kept address are two IPs, and a service on each)", field, family)
}

// ipTransition: an IP is one address from one place; it never changes.
func ipTransition(o, x *v1.IP) []string {
	if o.Spec != x.Spec {
		return []string{"spec can't change (type, family, hostAddress, provider, region): an IP is one address from one place; make another IP"}
	}
	return nil
}

// checkIPSet: an explicit type, and only the fields it takes; Static members each one address.
func checkIPSet(o *v1.IPSet) []string {
	sp := o.Spec
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	switch sp.Type {
	case v1.IPSetStatic:
		if len(sp.Members) == 0 {
			add("type Static needs members: one per instance, each { ip: NAME } or { hostAddress: NAME }")
		}
		if sp.Provider != "" || sp.Region != "" || sp.Max != 0 {
			add("type Static lists its members: provider, region and max are for type Dynamic")
		}
		if sp.Family != "" {
			add("type Static is its members' family: family is for type Dynamic (drop it; a set whose members differ is refused)")
		}
		seen := map[string]int{}
		for i, m := range sp.Members {
			f := fmt.Sprintf("members[%d]", i)
			switch {
			case (m.IP == "") == (m.HostAddress == ""):
				add("%s: exactly one of ip (an IP's name) and hostAddress (a host address's name)", f)
				continue
			case !label.MatchString(m.IP + m.HostAddress):
				add("%s: %q isn't a name (lower-case letters, digits, -)", f, m.IP+m.HostAddress)
			}
			if j, dup := seen[m.String()]; dup {
				add("%s: %s is members[%d] already: one address per ordinal", f, m.String(), j)
			}
			seen[m.String()] = i
		}
	case v1.IPSetDynamic:
		for _, m := range sp.Members {
			if m.HostAddress != "" {
				add("type Dynamic reserves provider IPs, so it can't have a host's address (hostAddress %s): use type Static with hostAddress members", m.HostAddress)
				break
			}
		}
		if len(sp.Members) > 0 {
			add("type Dynamic has no members: Kevaso reserves them as instances need them (SET-0, SET-1, …); list them with type Static instead")
		}
		if sp.Provider == "" || sp.Region == "" || sp.Max < 1 {
			add("type Dynamic needs provider, region and max (at least 1): who reserves the IPs, where, and how many at most")
		}
		if sp.Provider != "" && !label.MatchString(sp.Provider) {
			add("spec.provider %q: an installed provider's name (e.g. linode)", sp.Provider)
		}
		if f := checkFamily("spec.family", sp.Family); f != "" {
			add("%s", f)
		}
	case "":
		add("spec.type is required: Static (members you list) or Dynamic (provider IPs reserved as instances need them)")
	default:
		add("spec.type %q: Static or Dynamic", sp.Type)
	}
	return errs
}

// ipSetTransition: a set keeps its type and where it reserves; a Static set's members are only
// added at the end, never renumbered or removed (instance N keeps member N).
func ipSetTransition(o, x *v1.IPSet) []string {
	var errs []string
	if o.Spec.Family != x.Spec.Family {
		errs = append(errs, "spec.family can't change: its members are addresses of that family; make another set")
	}
	if o.Spec.Type != x.Spec.Type {
		return []string{"spec.type can't change (it's " + o.Spec.Type + "): make another IPSet"}
	}
	if o.Spec.Provider != x.Spec.Provider || o.Spec.Region != x.Spec.Region {
		errs = append(errs, "spec.provider and spec.region can't change: the set's IPs are reserved there; make another IPSet")
	}
	if len(x.Spec.Members) < len(o.Spec.Members) || !slices.Equal(o.Spec.Members, x.Spec.Members[:len(o.Spec.Members)]) {
		errs = append(errs, "members are only added at the end: an existing member never changes, moves or goes (instance N keeps member N); add new ones after the last")
	}
	return errs
}

// checkHostAddressList: a host's extra addresses, each a name, a kind and one address (IPv4 or IPv6), none
// twice and none a main IP. Names unique in the cluster is checked against the other hosts
// (checkHostAddresses).
func checkHostAddressList(h *v1.Host) []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	names, addrs := map[string]bool{}, map[string]string{}
	for _, a := range []string{h.Spec.ExternalIP, h.Spec.InternalIP, h.Spec.ExternalIPv6} {
		if a != "" {
			addrs[a] = "its main IP"
		}
	}
	for i, a := range h.Spec.Addresses {
		f := fmt.Sprintf("spec.addresses[%d]", i)
		if !label.MatchString(a.Name) {
			add("%s: name %q: lower-case letters, digits and - (an IP of type Host names it)", f, a.Name)
		}
		if names[a.Name] {
			add("%s: %s is listed twice", f, a.Name)
		}
		names[a.Name] = true
		if a.Kind != v1.NetworkExternal && a.Kind != v1.NetworkInternal {
			add("%s: kind %q: external (reachable from outside the host's network) or internal", f, a.Kind)
		}
		if _, err := ips.ParseAddress(a.Address); err != nil {
			add("%s: %v", f, err)
			continue
		}
		if who, ok := addrs[a.Address]; ok {
			add("%s: %s is %s already", f, a.Address, who)
		}
		addrs[a.Address] = a.Name
	}
	return errs
}
