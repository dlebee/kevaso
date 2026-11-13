package apiserver

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

var label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// checkPorts is admission for a silo's ports and service (design §7.0): declare, then open. Every
// service port names a declared port, once; allowFrom names silos; hostPort is internal and/or
// external; as and sources only where the port opens on the host or a load balancer; a
// loadBalancer port needs service.loadBalancer's class, which is there only for such ports. Pure.
func checkPorts(spec v1.SiloSpec) []string {
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
	if spec.Network.Egress.Source == v1.EgressPool && spec.Network.Egress.IP == "" && spec.LBClass() != v1.LBIPPool {
		add("network.egress.source pool needs egress.ip: an IP of class ip-pool (or ports on a load balancer of class ip-pool, whose IP it then sends from)")
	}
	sv := spec.Service
	if sv == nil {
		if spec.Network.Egress.Source == v1.EgressSameAsService {
			add("network.egress.source sameAsService needs a service with a port on the host or a load balancer: there's no address in to send from otherwise")
		}
		return errs
	}
	if sv.Name != "" && !label.MatchString(sv.Name) {
		add("service.name %q: lower-case letters, digits and -, at most 63", sv.Name)
	}
	opened := map[string]bool{}
	held := map[string]string{} // NETWORK NUMBER/PROTO → port
	lb, outside := false, false
	for _, p := range sv.Ports {
		f := "service.ports[" + p.Port + "]"
		d, ok := spec.Declared(p.Port)
		if !ok {
			add("%s: %q isn't a declared port (spec.ports): declare it first", f, p.Port)
			continue
		}
		if opened[p.Port] {
			add("%s: opened twice: put everything about one port in one entry", f)
		}
		opened[p.Port] = true
		for _, a := range p.AllowFrom {
			if a == "" || strings.Count(a, "/") > 1 || strings.HasPrefix(a, "/") || strings.HasSuffix(a, "/") {
				add("%s.allowFrom: %q: a silo, NAME or NAMESPACE/NAME", f, a)
			} else if _, err := netip.ParsePrefix(a); err == nil {
				add("%s.allowFrom: %q is a network range: allowFrom names silos; ranges go in sources (with hostPort or loadBalancer)", f, a)
			}
		}
		nets := map[string]bool{}
		for _, n := range p.HostPort {
			if n != v1.NetworkInternal && n != v1.NetworkExternal {
				add("%s.hostPort: %q: internal or external", f, n)
			}
			if nets[n] {
				add("%s.hostPort: %s twice", f, n)
			}
			nets[n] = true
		}
		if !p.Outside() {
			if p.As != 0 {
				add("%s.as: only with hostPort or loadBalancer (it's the number there)", f)
			}
			if len(p.Sources) > 0 {
				add("%s.sources: only with hostPort or loadBalancer (who may connect on its silo IP is allowFrom)", f)
			}
		}
		if p.As != 0 && (p.As < 1 || p.As > 65535) {
			add("%s.as: %d isn't from 1 to 65535", f, p.As)
		}
		for _, c := range p.Sources {
			if _, err := netip.ParsePrefix(c); err != nil {
				if _, err := netip.ParseAddr(c); err != nil {
					add("%s.sources: %q isn't an address or CIDR", f, c)
				}
			}
		}
		at := p.As
		if at == 0 {
			at = d.Port
		}
		for _, n := range p.HostPort {
			k := fmt.Sprintf("%s %d/%s", n, at, d.Proto())
			if other, ok := held[k]; ok {
				add("%s: %d/%s on the %s IP is %s's already", f, at, d.Proto(), n, other)
			}
			held[k] = p.Port
		}
		lb = lb || p.LoadBalancer
		outside = outside || p.Outside()
	}
	switch l := sv.LoadBalancer; {
	case lb && (l == nil || !label.MatchString(l.Class)):
		add("a port with loadBalancer: true needs service.loadBalancer.class: ip-pool, or a plugin's class (e.g. linode-nodebalancer)")
	case !lb && l != nil:
		add("service.loadBalancer is where ports with loadBalancer: true get their address, and no port says so")
	case l != nil && l.Dedicated && l.IP != "":
		add("service.loadBalancer.dedicated asks for an IP made for it alone: not with loadBalancer.ip (that one is named already)")
	}
	if spec.Network.Egress.Source == v1.EgressSameAsService && !outside {
		add("network.egress.source sameAsService needs a port on the host or a load balancer: there's no address in to send from otherwise")
	}
	return errs
}
