package kni

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Remember unions the allowFrom entries of prev and cur. A later table still resets a flow that
// was loaded once and is not allowed now; replacing the memory with only the latest table would
// drop that reset on the next reload and the established connection would resume. Grants are not
// kept: a removed or narrowed grant adds no cut, and new connections follow the grants loaded now.
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
		s.Egress = nil
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
	out.Spec = unionAllow(old.Spec, cur.Spec)
	out.Paths = unionPaths(old.Paths, cur.Paths)
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
	if len(old.Services) == 0 {
		return out
	}
	out.Services = append([]v1.SiloService(nil), cur.Services...)
	for _, osv := range old.Services {
		j := slices.IndexFunc(out.Services, func(sv v1.SiloService) bool { return sv.Name == osv.Name })
		if j < 0 {
			c := osv
			c.Ports = append([]v1.ServicePort(nil), osv.Ports...)
			out.Services = append(out.Services, c)
			continue
		}
		out.Services[j] = unionService(osv, out.Services[j])
	}
	return out
}

// unionService is cur with every port and allowFrom old has too.
func unionService(old, cur v1.SiloService) v1.SiloService {
	svc := cur
	svc.Ports = append([]v1.ServicePort(nil), cur.Ports...)
	idx := map[string]int{}
	for i := range svc.Ports {
		idx[svc.Ports[i].Port] = i
	}
	for _, p := range old.Ports {
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
	return svc
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
		for _, p := range s.open() {
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

func verdict(proto string) string {
	if proto == "tcp" {
		return "reject with tcp reset"
	}
	return "drop"
}

// revokeCuts are the resets for allowFrom flows prev allowed and cur does not. inet is both
// directions of a routed flow, loaded in the inet forward chain. bridge is a same-host flow, which
// never enters that chain; it is loaded in the bridge prerouting chain, where this family accepts
// reject (forward refuses it, and nft then refuses the whole table). Neither matches ct status
// dnat: a translated outside connection is not one of these flows.
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
	return inet, bridge
}
