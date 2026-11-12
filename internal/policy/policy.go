// Package policy turns a silo's grants into the policy of a runtime that enforces grants itself
// (OpenShell, research E037), and says what such a runtime can't enforce.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// maxPolicyPorts is the most ports one grant rule may open on a runtime that lists them one by one.
const maxPolicyPorts = 16

// For turns a silo's grants into a runtime policy (OpenShell: research E037). It returns what
// the runtime can't enforce as problems, so they're reported rather than silently not opened:
// address ranges (only single addresses), UDP, and delivery modes other than inject. Pure.
func For(s *v1.Silo, grants []*v1.Grant, injections []client.Injection) (kri.Policy, []string) {
	var p kri.Policy
	var problems []string
	seen := map[kri.Endpoint]bool{}
	add := func(e kri.Endpoint) {
		if !seen[e] {
			seen[e] = true
			p.Egress = append(p.Egress, e)
		}
	}
	for _, g := range v1.GrantsFor(s, grants) {
		for _, r := range g.Spec.Egress {
			e, err := r.Parse()
			if err != nil {
				problems = append(problems, fmt.Sprintf("grant %s: %v", g.Name, err))
				continue
			}
			host := e.Host
			if host == "" {
				if e.Prefix.Bits() != 32 {
					problems = append(problems, fmt.Sprintf("grant %s: %s is an address range; %s opens single addresses and names only", g.Name, r.To, s.Spec.Runtime))
					continue
				}
				host = e.Prefix.Addr().String()
			}
			for _, proto := range e.Protocols {
				if proto != "tcp" {
					problems = append(problems, fmt.Sprintf("grant %s: %s %s: %s has no UDP", g.Name, proto, r.To, s.Spec.Runtime))
				}
			}
			if !contains(e.Protocols, "tcp") {
				continue
			}
			ports := e.Ports
			if len(ports) == 0 {
				problems = append(problems, fmt.Sprintf("grant %s: %s needs ports on %s (it lists them one by one)", g.Name, r.To, s.Spec.Runtime))
				continue
			}
			n := 0
			for _, pr := range ports {
				n += pr.To - pr.From + 1
			}
			if n > maxPolicyPorts {
				problems = append(problems, fmt.Sprintf("grant %s: %s opens %d ports; at most %d on %s", g.Name, r.To, n, maxPolicyPorts, s.Spec.Runtime))
				continue
			}
			for _, pr := range ports {
				for port := pr.From; port <= pr.To; port++ {
					add(kri.Endpoint{Host: host, Port: port})
				}
			}
		}
		for _, sec := range g.Spec.Secrets {
			if sec.Delivery() != v1.DeliverInject {
				problems = append(problems, fmt.Sprintf("grant %s: secret %s: deliver %s isn't available on %s yet (inject is)", g.Name, sec.Name, sec.Delivery(), s.Spec.Runtime))
			}
		}
		if g.Spec.Operations != nil && g.Spec.Operations.Sign != nil {
			problems = append(problems, fmt.Sprintf("grant %s: sign isn't available on %s yet", g.Name, s.Spec.Runtime))
		}
	}
	for _, in := range injections {
		c := kri.Credential{Name: in.Secret, Env: in.Env, Host: in.Host, Header: in.Header, Value: in.Raw, Version: in.Version}
		switch {
		case strings.EqualFold(in.Header, "Authorization") && in.Format == "Bearer {{value}}":
			c.Bearer = true
		case in.Format == "{{value}}":
		default:
			problems = append(problems, fmt.Sprintf("secret %s: format %q: %s injects \"Bearer {{value}}\" or \"{{value}}\" only", in.Secret, in.Format, s.Spec.Runtime))
			continue
		}
		p.Credentials = append(p.Credentials, c)
		add(kri.Endpoint{Host: in.Host, Port: 443})
	}
	sort.Slice(p.Egress, func(i, j int) bool {
		a, b := p.Egress[i], p.Egress[j]
		return a.Host < b.Host || (a.Host == b.Host && a.Port < b.Port)
	})
	sort.Slice(p.Credentials, func(i, j int) bool {
		return p.Credentials[i].Name+p.Credentials[i].Host < p.Credentials[j].Name+p.Credentials[j].Host
	})
	return p, problems
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Check is what For would refuse for this silo, from its grants alone (admission: before any value
// exists).
func Check(s *v1.Silo, grants []*v1.Grant) []string {
	var inj []client.Injection
	for _, g := range v1.GrantsFor(s, grants) {
		for _, sec := range g.Spec.Secrets {
			if sec.Delivery() != v1.DeliverInject || sec.To == nil {
				continue
			}
			header, format := sec.To.Header, sec.To.Format
			if header == "" {
				header = "Authorization"
			}
			if format == "" {
				format = "Bearer {{value}}"
			}
			inj = append(inj, client.Injection{Host: sec.To.Host, Header: header, Format: format, Secret: sec.Name})
		}
	}
	_, problems := For(s, grants, inj)
	return problems
}

// SelfEnforced reports whether a runtime enforces grants itself (no host firewall or egress gate).
func SelfEnforced(runtime string) bool {
	return runtime == "openshell" || runtime == "openshell-container"
}
