package kni

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Remember unions the grants and allowFrom entries of prev and cur. A later table still resets a
// flow that was loaded once and is not allowed now; replacing the memory with only the latest
// table would drop that reset on the next reload and the established connection would resume.
func Remember(prev, cur Host) Host {
	out := cur
	out.Revoke = nil
	out.Local = unionSilos(prev.Local, cur.Local)
	out.All = unionSilos(prev.All, cur.All)
	return out
}

func unionSilos(a, b []Silo) []Silo {
	by := map[string]Silo{}
	var order []string
	add := func(s Silo) {
		old, ok := by[s.Key]
		if !ok {
			order = append(order, s.Key)
			by[s.Key] = s
			return
		}
		by[s.Key] = mergeSilo(old, s)
	}
	for _, s := range a {
		if s.Key != "" {
			add(s)
		}
	}
	for _, s := range b {
		if s.Key != "" {
			add(s)
		}
	}
	out := make([]Silo, 0, len(order))
	for _, k := range order {
		out = append(out, by[k])
	}
	return out
}

func mergeSilo(old, cur Silo) Silo {
	out := cur
	if !out.IP.IsValid() {
		out.IP = old.IP
	}
	out.Egress = unionEgress(old.Egress, cur.Egress)
	out.Spec = unionAllow(old.Spec, cur.Spec)
	out.Paths = unionPaths(old.Paths, cur.Paths)
	return out
}

func unionEgress(a, b []v1.ParsedEgress) []v1.ParsedEgress {
	seen := map[string]bool{}
	var out []v1.ParsedEgress
	for _, e := range append(append([]v1.ParsedEgress(nil), a...), b...) {
		k := e.Prefix.String() + " " + e.Host + " " + strings.Join(e.Protocols, ",")
		for _, p := range e.Ports {
			k += " " + p.String()
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

func unionAllow(old, cur v1.SiloSpec) v1.SiloSpec {
	out := cur
	havePort := map[string]bool{}
	for _, p := range out.Ports {
		havePort[p.Name] = true
	}
	for _, p := range old.Ports {
		if !havePort[p.Name] {
			out.Ports = append(out.Ports, p)
		}
	}
	if old.Service == nil {
		return out
	}
	svc := v1.SiloService{}
	if out.Service != nil {
		svc = *out.Service
		svc.Ports = append([]v1.ServicePort(nil), out.Service.Ports...)
	}
	idx := map[string]int{}
	for i := range svc.Ports {
		idx[svc.Ports[i].Port] = i
	}
	for _, p := range old.Service.Ports {
		i, ok := idx[p.Port]
		if !ok {
			p.AllowFrom = append([]string(nil), p.AllowFrom...)
			idx[p.Port] = len(svc.Ports)
			svc.Ports = append(svc.Ports, p)
			continue
		}
		have := map[string]bool{}
		for _, n := range svc.Ports[i].AllowFrom {
			have[n] = true
		}
		for _, n := range p.AllowFrom {
			if !have[n] {
				svc.Ports[i].AllowFrom = append(svc.Ports[i].AllowFrom, n)
				have[n] = true
			}
		}
	}
	out.Service = &svc
	return out
}

func unionPaths(a, b map[string][]string) map[string][]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := map[string][]string{}
	add := func(m map[string][]string) {
		for k, vs := range m {
			have := map[string]bool{}
			for _, v := range out[k] {
				have[v] = true
			}
			for _, v := range vs {
				if !have[v] {
					out[k] = append(out[k], v)
					have[v] = true
				}
			}
		}
	}
	add(a)
	add(b)
	return out
}

type flow struct {
	src, dst netip.Addr
	proto    string
	port     int
}

func (f flow) key() string {
	return f.src.String() + " " + f.dst.String() + " " + f.proto + " " + fmt.Sprint(f.port)
}

// flowsOf is the silo-to-silo flows h allows: allowFrom and ingress paths, by the caller's
// current address. A host-name grant is not here; it has no address in these rules.
func flowsOf(h Host) map[flow]bool {
	byKey := map[string]Silo{}
	for _, s := range h.All {
		byKey[s.Key] = s
	}
	for _, s := range h.Local {
		if s.IP.Is4() {
			byKey[s.Key] = s
		}
	}
	out := map[flow]bool{}
	for _, s := range h.Local {
		if !s.IP.Is4() {
			continue
		}
		ns := s.Key
		if i := strings.IndexByte(s.Key, '/'); i >= 0 {
			ns = s.Key[:i]
		}
		for _, p := range s.Spec.Open() {
			proto := lower(p.Protocol)
			if !okPort(p.Number) || !okProto(proto) {
				continue
			}
			var callers []string
			callers = append(callers, p.AllowFrom...)
			callers = append(callers, s.Paths[p.Name]...)
			seen := map[string]bool{}
			for _, key := range callers {
				if !strings.Contains(key, "/") {
					key = ns + "/" + key
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				src, ok := byKey[key]
				if !ok || !src.IP.Is4() {
					continue
				}
				out[flow{src: src.IP, dst: s.IP, proto: proto, port: p.Number}] = true
			}
		}
	}
	return out
}

type egUnit struct {
	ip     netip.Addr
	prefix netip.Prefix
	proto  string
	all    bool
	ports  v1.PortRange
}

func (u egUnit) key() string {
	ps := "*"
	if !u.all {
		ps = u.ports.String()
	}
	return u.ip.String() + " " + u.prefix.String() + " " + u.proto + " " + ps
}

func egressUnits(h Host) []egUnit {
	var out []egUnit
	for _, s := range h.Local {
		if !s.IP.Is4() {
			continue
		}
		for _, e := range s.Egress {
			if !e.Prefix.IsValid() || !e.Prefix.Addr().Is4() {
				continue // a host name is spliced by the gate; these rules have no address to reset
			}
			protos := e.Protocols
			if len(protos) == 0 {
				protos = []string{"tcp"}
			}
			for _, proto := range protos {
				proto = lower(proto)
				if !okProto(proto) {
					continue
				}
				if len(e.Ports) == 0 {
					out = append(out, egUnit{ip: s.IP, prefix: e.Prefix.Masked(), proto: proto, all: true})
					continue
				}
				for _, p := range e.Ports {
					if !okPort(p.From) || !okPort(p.To) || p.From > p.To {
						continue
					}
					out = append(out, egUnit{ip: s.IP, prefix: e.Prefix.Masked(), proto: proto, ports: p})
				}
			}
		}
	}
	return out
}

func coversPrefix(wider, inner netip.Prefix) bool {
	return wider.IsValid() && inner.IsValid() && wider.Contains(inner.Addr()) && wider.Bits() <= inner.Bits()
}

func coversUnit(have egUnit, want egUnit) bool {
	if have.ip != want.ip || have.proto != want.proto || !coversPrefix(have.prefix, want.prefix) {
		return false
	}
	if want.all {
		return have.all
	}
	if have.all {
		return true
	}
	return have.ports.From <= want.ports.From && have.ports.To >= want.ports.To
}

func verdict(proto string) string {
	if proto == "tcp" {
		return "reject with tcp reset"
	}
	return "drop"
}

func portExpr(proto string, all bool, ports v1.PortRange, dir string) string {
	if all {
		return "meta l4proto " + proto
	}
	if ports.From == ports.To {
		return fmt.Sprintf("%s %s %d", proto, dir, ports.From)
	}
	return fmt.Sprintf("%s %s %s", proto, dir, ports.String())
}

func notSet(field string, addrs []string) string {
	if len(addrs) == 0 {
		return ""
	}
	sort.Strings(addrs)
	if len(addrs) == 1 {
		return field + " != " + addrs[0] + " "
	}
	return field + " != { " + strings.Join(addrs, ", ") + " } "
}

// revokeCuts are the resets for flows prev allowed and cur does not. inet is both directions of
// a routed flow (and an allowFrom flow); bridge is a same-host allowFrom flow, which never enters
// the inet forward chain. Neither matches ct status dnat: a translated outside connection is not
// one of these flows.
func revokeCuts(cur, prev Host) (inet, bridge []string) {
	now := flowsOf(cur)
	var gone []flow
	for f := range flowsOf(prev) {
		if !now[f] {
			gone = append(gone, f)
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i].key() < gone[j].key() })
	for _, f := range gone {
		v := verdict(f.proto)
		inet = append(inet,
			fmt.Sprintf("oifname %q ip saddr %s ip daddr %s %s dport %d %s", cur.Bridge, f.src, f.dst, f.proto, f.port, v),
			fmt.Sprintf("iifname %q ip saddr %s ip daddr %s %s sport %d %s", cur.Bridge, f.dst, f.src, f.proto, f.port, v),
		)
		if cur.Subnet.IsValid() && cur.Subnet.Contains(f.src) {
			bridge = append(bridge,
				fmt.Sprintf("ip saddr %s ip daddr %s %s dport %d %s", f.src, f.dst, f.proto, f.port, v),
				fmt.Sprintf("ip saddr %s ip daddr %s %s sport %d %s", f.dst, f.src, f.proto, f.port, v),
			)
		}
	}

	current := egressUnits(cur)
	var units []egUnit
	seen := map[string]bool{}
	for _, u := range egressUnits(prev) {
		if seen[u.key()] {
			continue
		}
		seen[u.key()] = true
		full := false
		for _, c := range current {
			if coversUnit(c, u) && c.prefix.Bits() <= u.prefix.Bits() && coversPrefix(c.prefix, u.prefix) {
				full = true
				break
			}
		}
		if !full {
			units = append(units, u)
		}
	}
	sort.Slice(units, func(i, j int) bool { return units[i].key() < units[j].key() })
	for _, u := range units {
		var excl []string
		have := map[string]bool{}
		for _, c := range current {
			if c.ip != u.ip || c.proto != u.proto || !coversUnit(c, egUnit{ip: u.ip, prefix: c.prefix, proto: u.proto, all: u.all, ports: u.ports}) {
				continue
			}
			if !u.prefix.Contains(c.prefix.Addr()) || u.prefix.Bits() > c.prefix.Bits() {
				continue // not inside the range being cut
			}
			if c.prefix.Bits() == u.prefix.Bits() {
				continue // the same range: it would have fully covered the unit
			}
			s := c.prefix.String()
			if !have[s] {
				have[s] = true
				excl = append(excl, s)
			}
		}
		v := verdict(u.proto)
		inet = append(inet,
			cutLine("iifname", cur.Bridge, "ip saddr "+u.ip.String(), "ip daddr "+u.prefix.String(), notSet("ip daddr", excl), portExpr(u.proto, u.all, u.ports, "dport"), v),
			cutLine("oifname", cur.Bridge, "ip daddr "+u.ip.String(), "ip saddr "+u.prefix.String(), notSet("ip saddr", excl), portExpr(u.proto, u.all, u.ports, "sport"), v),
		)
	}
	return inet, bridge
}

func cutLine(dir, bridge string, parts ...string) string {
	b := strings.Builder{}
	fmt.Fprintf(&b, "%s %q", dir, bridge)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(p)
	}
	return b.String()
}
