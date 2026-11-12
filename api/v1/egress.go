package v1

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// PortRange is an inclusive range of ports.
type PortRange struct{ From, To int }

func (p PortRange) String() string {
	if p.From == p.To {
		return strconv.Itoa(p.From)
	}
	return fmt.Sprintf("%d-%d", p.From, p.To)
}

// ParsedEgress is a parsed EgressRule: either a CIDR (Prefix valid) or a host name.
type ParsedEgress struct {
	Prefix    netip.Prefix
	Host      string      // lower-case; "*.example.com" matches one or more labels under it
	Ports     []PortRange // empty: every port (CIDR only)
	Protocols []string    // tcp, udp
}

// Parse checks and parses the rule.
func (r EgressRule) Parse() (ParsedEgress, error) {
	var e ParsedEgress
	to := strings.TrimSpace(r.To)
	if to == "" {
		return e, fmt.Errorf("egress: to is required")
	}
	if p, err := netip.ParsePrefix(to); err == nil {
		if !p.Addr().Is4() {
			return e, fmt.Errorf("egress %q: IPv6 comes later; IPv4 for now", to)
		}
		e.Prefix = p.Masked()
	} else if a, err := netip.ParseAddr(to); err == nil {
		if !a.Is4() {
			return e, fmt.Errorf("egress %q: IPv6 comes later; IPv4 for now", to)
		}
		e.Prefix = netip.PrefixFrom(a, 32)
	} else {
		h := strings.ToLower(strings.TrimSuffix(to, "."))
		if !validHostPattern(h) {
			return e, fmt.Errorf("egress %q: not a CIDR, an address or a host name", to)
		}
		e.Host = h
	}
	for _, s := range r.Ports {
		pr, err := parsePorts(s)
		if err != nil {
			return e, fmt.Errorf("egress %q: %w", to, err)
		}
		e.Ports = append(e.Ports, pr)
	}
	for _, p := range r.Protocols {
		p = strings.ToLower(p)
		if p != "tcp" && p != "udp" {
			return e, fmt.Errorf("egress %q: protocol %q: tcp or udp", to, p)
		}
		e.Protocols = append(e.Protocols, p)
	}
	if len(e.Protocols) == 0 {
		e.Protocols = []string{"tcp"}
	}
	if e.Host != "" {
		if len(e.Protocols) != 1 || e.Protocols[0] != "tcp" {
			return e, fmt.Errorf("egress %q: a host name only opens TLS over TCP (the gate checks the name the client asks for); use a CIDR for UDP", to)
		}
		if len(e.Ports) == 0 {
			e.Ports = []PortRange{{443, 443}}
		}
	}
	return e, nil
}

func parsePorts(s string) (PortRange, error) {
	from, to, isRange := strings.Cut(strings.TrimSpace(s), "-")
	a, err := strconv.Atoi(from)
	if err != nil || a < 1 || a > 65535 {
		return PortRange{}, fmt.Errorf("port %q: want 1-65535 or a range like 30000-30100", s)
	}
	b := a
	if isRange {
		if b, err = strconv.Atoi(to); err != nil || b < a || b > 65535 {
			return PortRange{}, fmt.Errorf("port %q: want 1-65535 or a range like 30000-30100", s)
		}
	}
	return PortRange{a, b}, nil
}

func validHostPattern(h string) bool {
	h = strings.TrimPrefix(h, "*.")
	if len(h) == 0 || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// MatchHost reports whether name (what a client asked for) matches pattern ("api.github.com" or
// "*.github.com", which doesn't match github.com itself).
func MatchHost(pattern, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(name, "."+suffix) && len(name) > len(suffix)+1
	}
	return name == pattern
}

// AllowsPort reports whether port is in the rule's ports (all, if none listed).
func (e ParsedEgress) AllowsPort(port int) bool {
	if len(e.Ports) == 0 {
		return true
	}
	for _, p := range e.Ports {
		if port >= p.From && port <= p.To {
			return true
		}
	}
	return false
}
