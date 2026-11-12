// Package kni is the built-in silo networking on a worker (design §7: KNI "bridge"): the host's
// nftables rules for its silos, generated from the API, applied atomically. Pure here; Apply runs
// nft.
//
// Default deny, as the design's table says: no silo reaches another silo's ports (on this host or
// across the mesh) unless the receiving silo's allowFrom opens them; nothing outside reaches a silo
// unless its service is exposed; a silo reaches nothing outside the cluster unless one of its
// Grants opens it (raw TCP/UDP to a CIDR here; host names through the egress gate); silos can't
// reach the mesh's host addresses, nor their own host beyond DNS and ping. Exposed ports are DNAT (the client's address is kept: E009), and a silo's
// outbound source is SNAT to its service's or its pool's address when it asks.
package kni

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Silo is what the rules need about one silo.
type Silo struct {
	Key  string // namespace/name
	IP   netip.Addr
	Tap  string // its tap device on the bridge (local silos only)
	Spec v1.SiloSpec
	// PublicIP is where it's reached from outside (hostPort / worker-ip: the host's address,
	// ip-pool: its pool address); EgressIP where its traffic leaves from ("" = the host default).
	PublicIP netip.Addr
	EgressIP netip.Addr
	// Egress is what its Grants open outside the cluster (CIDR rules; host names go through the
	// egress gate).
	Egress []v1.ParsedEgress
}

// Host is one worker's view.
type Host struct {
	Bridge  string
	Subnet  netip.Prefix // this host's silos
	Gateway netip.Addr
	Address netip.Addr // the host's own (public, if it has one) address
	Local   []Silo     // silos on this host
	All     []Silo     // every silo in the cluster with an address, to resolve allowFrom sources
}

// Prefixes no silo may reach directly: the mesh's host addresses.
const meshHosts = "{ 10.62.0.0/16, 10.63.0.0/16 }"
const silosAll = "10.64.0.0/16"

type rule struct {
	proto string // tcp | udp
	port  int
}

func protoOf(p v1.ServicePort) string {
	if strings.EqualFold(p.Protocol, "UDP") {
		return "udp"
	}
	return "tcp"
}

// ports resolves port names on s's service ("" or empty list = all).
func ports(s v1.SiloSpec, names []string) []rule {
	if s.Service == nil {
		return nil
	}
	var out []rule
	for _, p := range s.Service.Ports {
		if len(names) == 0 || contains(names, p.Name) {
			out = append(out, rule{protoOf(p), p.Port})
		}
	}
	return out
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Exposed returns the ports s opens to the outside and from which sources (nil: anywhere).
func Exposed(s v1.SiloSpec) ([]rule, []string) {
	sv := s.Service
	if sv == nil {
		return nil, nil
	}
	switch sv.Expose {
	case v1.ExposeHostPort:
		if sv.HostPort == nil {
			return ports(s, nil), nil
		}
		return ports(s, sv.HostPort.Ports), sv.HostPort.AllowFrom
	case v1.ExposeLoadBalancer:
		var from []string
		if sv.LoadBalancer != nil {
			from = sv.LoadBalancer.AllowFrom
		}
		return ports(s, nil), from
	}
	return nil, nil
}

func set(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

// Rules is the host's whole silo ruleset, ready for `nft -f` (it replaces the previous one
// atomically). Deterministic: the same input gives the same text, so unchanged means no reload.
func Rules(h Host) string {
	local := append([]Silo(nil), h.Local...)
	sort.Slice(local, func(i, j int) bool { return local[i].Key < local[j].Key })
	byKey := map[string]Silo{}
	for _, s := range h.All {
		byKey[s.Key] = s
	}
	for _, s := range local {
		byKey[s.Key] = s
	}
	var dnat, snat, fwd, br, egress []string
	for _, s := range local {
		if !s.IP.IsValid() {
			continue
		}
		// Exposure: DNAT from its public address, then let through only the allowed sources.
		exp, from := Exposed(s.Spec)
		if s.PublicIP.IsValid() {
			for _, r := range exp {
				dnat = append(dnat, fmt.Sprintf("ip daddr %s %s dport %d dnat ip to %s:%d", s.PublicIP, r.proto, r.port, s.IP, r.port))
				src := ""
				if len(from) > 0 {
					src = "ip saddr " + set(from) + " "
				}
				fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d ct status dnat accept", h.Bridge, s.IP, src, r.proto, r.port))
			}
		}
		// Outbound: only what its grants open.
		for _, e := range s.Egress {
			if !e.Prefix.IsValid() {
				continue
			}
			for _, proto := range e.Protocols {
				m := fmt.Sprintf("iifname %q ip saddr %s ip daddr %s ", h.Bridge, s.IP, e.Prefix)
				if len(e.Ports) == 0 {
					egress = append(egress, m+"meta l4proto "+proto+" accept")
					continue
				}
				ps := make([]string, len(e.Ports))
				for i, p := range e.Ports {
					ps[i] = p.String()
				}
				egress = append(egress, m+proto+" dport "+set(ps)+" accept")
			}
		}
		// Outbound source.
		if s.EgressIP.IsValid() {
			snat = append(snat, fmt.Sprintf("ip saddr %s ip daddr != { %s, 10.62.0.0/16, 10.63.0.0/16 } oifname != %q snat ip to %s", s.IP, silosAll, h.Bridge, s.EgressIP))
		}
		// allowFrom: other silos, by their current address, to the named ports.
		ns := strings.SplitN(s.Key, "/", 2)[0]
		for _, a := range s.Spec.AllowFrom {
			key := a.Silo
			if !strings.Contains(key, "/") {
				key = ns + "/" + key
			}
			src, ok := byKey[key]
			if !ok || !src.IP.IsValid() {
				continue // not running anywhere right now: nothing to open
			}
			for _, r := range ports(s.Spec, a.Ports) {
				m := fmt.Sprintf("ip saddr %s ip daddr %s %s dport %d accept", src.IP, s.IP, r.proto, r.port)
				if h.Subnet.Contains(src.IP) {
					br = append(br, m) // same host: bridged
				} else {
					fwd = append(fwd, fmt.Sprintf("oifname %q %s", h.Bridge, m)) // across the mesh: routed
				}
			}
		}
	}

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("table inet kevaso")
	w("delete table inet kevaso")
	w("table inet kevaso {")
	w("  chain prerouting {")
	w("    type nat hook prerouting priority dstnat; policy accept;")
	for _, r := range dnat {
		w("    %s", r)
	}
	w("  }")
	w("  chain postrouting {")
	w("    type nat hook postrouting priority srcnat; policy accept;")
	for _, r := range snat {
		w("    %s", r)
	}
	w("    ip saddr %s ip daddr != { %s, 10.62.0.0/16, 10.63.0.0/16 } oifname != %q masquerade", h.Subnet, silosAll, h.Bridge)
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
	w("    iifname %q ip daddr %s drop", h.Bridge, meshHosts)
	w("    oifname %q ct state established,related accept", h.Bridge)
	for _, r := range fwd {
		w("    %s", r)
	}
	w("    oifname %q drop", h.Bridge)
	// From silos: replies, other silos (over the mesh: their host decides), then grants only.
	w("    iifname %q ct state established,related accept", h.Bridge)
	w("    iifname %q ip daddr %s accept", h.Bridge, silosAll)
	for _, r := range egress {
		w("    %s", r)
	}
	w("    iifname %q drop", h.Bridge)
	w("  }")
	w("  chain input {")
	w("    type filter hook input priority filter; policy accept;")
	w("    iifname %q ct state established,related accept", h.Bridge)
	w("    iifname %q ip daddr %s udp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s tcp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s icmp type echo-request accept", h.Bridge, h.Gateway)
	w("    iifname %q drop", h.Bridge)
	w("  }")
	w("}")
	w("table bridge kevaso")
	w("delete table bridge kevaso")
	w("table bridge kevaso {")
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
	for _, s := range local {
		if s.Tap != "" && s.IP.IsValid() {
			w("    iifname %q ip saddr != %s drop", s.Tap, s.IP)     // no silo speaks for another…
			w("    iifname %q arp saddr ip != %s drop", s.Tap, s.IP) // …nor claims its address
		}
	}
	w("    ether type arp accept") // silos must find each other's MAC before allowFrom can matter
	w("    ct state established,related accept")
	for _, r := range br {
		w("    %s", r)
	}
	w("    iifname \"kvt*\" oifname \"kvt*\" drop")
	w("  }")
	w("}")
	// Tables from before M6, if a host still has them.
	for _, old := range []string{"inet kevaso_nat", "bridge kevaso_silos"} {
		w("table %s", old)
		w("delete table %s", old)
	}
	return b.String()
}
