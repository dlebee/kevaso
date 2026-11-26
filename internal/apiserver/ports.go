package apiserver

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

var label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// checkPorts is admission for a silo's ports and services (design §7.0, networking v2): declare,
// then open, one way in per service. silo is the silo's name (an unnamed service's); inSet: the
// silo is a SiloSet's instance (own is its IPSet member). Pure.
func checkPorts(spec v1.SiloSpec, silo string, inSet bool) []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	seen := map[string]bool{}
	numbers := map[string]string{}
	for _, p := range spec.Ports {
		if !label.MatchString(p.Name) {
			add("spec.ports: %q: a port needs a name (lower-case letters, digits, -)", p.Name)
		}
		if seen[p.Name] {
			add("spec.ports: %s is declared twice", p.Name)
		}
		seen[p.Name] = true
		if p.Port < 1 || p.Port > 65535 {
			add("spec.ports[%s]: port %d isn't from 1 to 65535", p.Name, p.Port)
		}
		if p.Protocol != "" && p.Protocol != "TCP" && p.Protocol != "UDP" {
			add("spec.ports[%s]: protocol %q: TCP or UDP", p.Name, p.Protocol)
		}
		k := fmt.Sprintf("%d/%s", p.Port, p.Proto())
		if other, ok := numbers[k]; ok {
			add("spec.ports: %s and %s are both %s", other, p.Name, k)
		}
		numbers[k] = p.Name
	}
	errs = append(errs, checkEgress(spec, inSet)...)
	names := map[string]int{}
	held := map[string]string{} // WAY NUMBER/PROTO → service/port
	for i, sv := range spec.Services {
		f := fmt.Sprintf("services[%d]", i)
		if sv.Name != "" {
			f = "service " + sv.Name
			if !label.MatchString(sv.Name) {
				add("%s: name %q: lower-case letters, digits and -, at most 63", f, sv.Name)
			}
		}
		n := v1.ServiceNameOf(sv, silo)
		if j, dup := names[n]; dup {
			add("services[%d] and services[%d] are both named %s (an unnamed service takes the silo's name): each service its own name (name: web, name: api)", j, i, n)
		}
		names[n] = i
		errs = append(errs, checkWay(f, sv, inSet)...)
		if len(sv.Ports) == 0 {
			add("%s: no ports: a service opens at least one declared port", f)
		}
		t := sv.TypeOrDefault()
		way := sv.Way()
		opened := map[string]bool{}
		for _, p := range sv.Ports {
			pf := f + ": ports[" + p.Port + "]"
			d, ok := spec.Declared(p.Port)
			if !ok {
				add("%s: %q isn't a declared port (spec.ports): declare it first", pf, p.Port)
				continue
			}
			if opened[p.Port] {
				add("%s: listed twice in one service: put everything about one port in one entry", pf)
			}
			opened[p.Port] = true
			for _, a := range p.AllowFrom {
				if a == "" || strings.Count(a, "/") > 1 || strings.HasPrefix(a, "/") || strings.HasSuffix(a, "/") {
					add("%s.allowFrom: %q: a silo, NAME or NAMESPACE/NAME", pf, a)
				} else if _, err := netip.ParsePrefix(a); err == nil {
					add("%s.allowFrom: %q is a network range: allowFrom names silos; ranges go in sources (on a HostPort or LoadBalancer service)", pf, a)
				}
			}
			if t == v1.ServiceInternal {
				if p.As != 0 {
					add("%s.as: only on a HostPort or LoadBalancer service (it's the number there); an Internal port is reached on its own number", pf)
				}
				if len(p.Sources) > 0 {
					add("%s.sources: only on a HostPort or LoadBalancer service; who may connect over the mesh is allowFrom", pf)
				}
			}
			if p.Lease != nil && t != v1.ServiceHostPort {
				add("%s.lease: leases are on HostPort services only (silo-to-silo access is allowFrom; put the port in a HostPort service to lease it)", pf)
			}
			if p.As != 0 && (p.As < 1 || p.As > 65535) {
				add("%s.as: %d isn't from 1 to 65535", pf, p.As)
			}
			for _, c := range p.Sources {
				if _, err := v1.ParseSource(c); err != nil {
					add("%s.sources: %v", pf, err)
				}
			}
			if t != v1.ServiceHostPort {
				continue
			}
			at := p.As
			if at == 0 {
				at = d.Port
			}
			if why := v1.ReservedHostPort(at); why != "" { // a number the platform listens on
				add("%s: %d is %s, which a silo may not take", pf, at, why)
			}
			k := fmt.Sprintf("%s %d/%s", way.String(), at, d.Proto())
			if other, ok := held[k]; ok && way.String() != "" {
				add("%s: %d/%s on %s is %s's already: one port per number on an address", pf, at, d.Proto(), way.String(), other)
			}
			held[k] = v1.ServiceNameOf(sv, "the silo's service") + " " + p.Port
		}
	}
	return errs
}

// checkWay is one service's way in: its type, and only the fields that type takes, exactly one
// way in each (networking v2's "can never work" list).
func checkWay(f string, sv v1.SiloService, inSet bool) []string {
	var errs []string
	add := func(m string, a ...any) { errs = append(errs, fmt.Sprintf(f+": "+m, a...)) }
	t := sv.TypeOrDefault()
	switch t {
	case v1.ServiceInternal, v1.ServiceHostPort, v1.ServiceLoadBalancer:
	default:
		add("type %q: Internal (silos in allowFrom, over the mesh), HostPort (at the worker running it) or LoadBalancer (a provider's balancer in front)", sv.Type)
		return errs
	}
	if sv.HostPort != nil && t != v1.ServiceHostPort {
		add("hostPort goes with type: HostPort; this one is %s (two ways in: make a second service for the other)", t)
	}
	if sv.LoadBalancer != nil && t != v1.ServiceLoadBalancer {
		add("loadBalancer goes with type: LoadBalancer; this one is %s (two ways in: make a second service for the other)", t)
	}
	if h := sv.HostPort; h != nil && t == v1.ServiceHostPort {
		switch {
		case h.Ways() == 0:
			add("hostPort: say one of worker (external or internal), ip (an IP's name) or own: true; or leave hostPort out for { worker: external }")
		case h.Ways() > 1:
			add("hostPort takes exactly one of worker, ip and own (two ways in inside one service): make a service for each")
		case h.Worker != "" && h.Worker != v1.NetworkExternal && h.Worker != v1.NetworkInternal:
			add("hostPort.worker %q: external or internal (the worker's main IPs)", h.Worker)
		case h.IP != "" && !label.MatchString(h.IP):
			add("hostPort.ip %q: an IP's name in this namespace (no kind/ prefix)", h.IP)
		case h.Own && !inSet:
			add("hostPort.own is a SiloSet instance's own IPSet member: a single silo names its address with hostPort.ip (an IP), or put it in a SiloSet with ips: SETNAME")
		}
	}
	if t == v1.ServiceLoadBalancer {
		switch l := sv.LoadBalancer; {
		case l == nil || l.Provider == "":
			add("type LoadBalancer needs loadBalancer.provider: the installed provider making the balancer (e.g. linode)")
		case !label.MatchString(l.Provider):
			add("loadBalancer.provider %q: an installed provider's name (e.g. linode)", l.Provider)
		case l.IP != "" && !label.MatchString(l.IP):
			add("loadBalancer.ip %q: an IP's name in this namespace (no kind/ prefix)", l.IP)
		}
	}
	return errs
}

// checkEgress is network.egress.source: exactly one of ip and own; own only in a SiloSet.
func checkEgress(spec v1.SiloSpec, inSet bool) []string {
	src := spec.Network.Egress.Source
	switch {
	case src == nil:
		return nil
	case src.Ways() != 1:
		return []string{"network.egress.source takes exactly one of ip (an IP's name) and own: true; leave it out to send from the worker's own IP"}
	case src.IP != "" && !label.MatchString(src.IP):
		return []string{fmt.Sprintf("network.egress.source.ip %q: an IP's name in this namespace (no kind/ prefix)", src.IP)}
	case src.Own && !inSet:
		return []string{"network.egress.source.own is a SiloSet instance's own IPSet member: a single silo names its address with egress.source.ip (an IP), or put it in a SiloSet with ips: SETNAME"}
	}
	return nil
}

// checkTemplate is admission for what a SiloSet's template may say about addresses: never one IP
// (many instances can't share one address, even with one instance), and ips: SETNAME exactly when
// the template uses own.
func checkTemplate(set *v1.SiloSet) []string {
	var errs []string
	for _, n := range set.Spec.Template.NamedIPs() {
		errs = append(errs, fmt.Sprintf("template.%s names IP %s: one IP can't serve many instances (even with one instance): use own: true and put the set on an IPSet (ips: SETNAME)", n.Field, n.Name))
	}
	uses := set.Spec.Template.UsesOwn()
	switch {
	case uses && set.Spec.IPs == "":
		errs = append(errs, "the template says own, so the set needs ips: SETNAME (an IPSet whose member N is instance N's address)")
	case !uses && set.Spec.IPs != "":
		errs = append(errs, "spec.ips "+set.Spec.IPs+" is only used with own: nothing in the template says own (hostPort: { own: true } or egress.source: { own: true }): drop ips, or use own")
	case set.Spec.IPs != "" && !label.MatchString(set.Spec.IPs):
		errs = append(errs, fmt.Sprintf("spec.ips %q: an IPSet's name in this namespace", set.Spec.IPs))
	}
	return errs
}
