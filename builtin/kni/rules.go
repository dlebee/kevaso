// Package kni is the built-in silo networking on a worker (design §7: KNI "bridge"): the host's
// nftables rules for its silos, generated from the API, applied atomically. Pure here; Apply runs
// nft.
//
// Default deny, as the design's table says: no silo reaches another silo's ports (on this host or
// across the mesh) unless the receiving silo's allowFrom opens them; nothing outside reaches a silo
// unless its service is exposed; a silo reaches nothing outside the cluster unless one of its
// Grants opens it (raw TCP/UDP to a CIDR here; host names through the egress gate); silos can't
// reach the mesh's host addresses, nor their own host beyond DNS, ping and, for a silo whose grants
// need one, its local endpoint (ADR 0008). Exposed ports are DNAT (the client's address is kept: E009), and a silo's
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
	// GatePorts are the TCP ports its traffic outside the cluster goes to the egress gate on
	// (grants by host name, injected secrets).
	GatePorts []v1.PortRange
	// NodePorts are host ports a plugin's load balancer sends its service ports to, from
	// SourceRanges only (a NodeBalancer's addresses).
	NodePorts    []v1.NodePort
	SourceRanges []string
	// Endpoint: the silo reaches its host's local endpoint (Host.Endpoint, port 80).
	Endpoint bool
	// Leases (design §7.2d): Leased are the exposed ports (by name) that open only on a lease, and
	// Closed those of them with no active lease now: a closed port has no outside rule at all, and
	// connections that a lease let in are cut (reset) once it ends. An open leased port takes
	// LeaseFrom as its sources when set (the service's allowFrom narrowed by the lease's). Private
	// access (allowFrom on the silo) is never leased.
	Leased    []string
	Closed    []string
	LeaseFrom []string
}

// Service is a standalone Service as the rules need it (design §7.1): its virtual IP, sent to its
// endpoints from this host's silos (like kube-proxy), and for a load balancer, its node ports sent
// to the endpoints on this host only (from the load balancer's addresses: client addresses kept).
type Service struct {
	Key          string // namespace/name
	ClusterIP    netip.Addr
	Ports        []ServicePort
	SourceRanges []string
}

// ServicePort is one port of a Service and where it goes.
type ServicePort struct {
	Proto    string // tcp | udp
	Port     int
	NodePort int // 0: none
	Targets  []Target
}

// Target is one endpoint of a port.
type Target struct {
	IP    netip.Addr
	Port  int
	Local bool // on this host
}

// Host is one worker's view.
type Host struct {
	Bridge  string
	Subnet  netip.Prefix // this host's silos
	Gateway netip.Addr
	Address netip.Addr // the host's own (public, if it has one) address
	Local   []Silo     // silos on this host
	All     []Silo     // every silo in the cluster with an address, to resolve allowFrom sources
	// GatePort is where the egress gate listens on the gateway (0: no gate).
	GatePort int
	// Endpoint is the silos' local endpoint's address on the bridge (invalid: none): reached on
	// port 80 from the bridge only, by the silos that have one.
	Endpoint netip.Addr
	// Services are the cluster's standalone Services with endpoints.
	Services []Service
}

// Prefixes no silo may reach directly: the mesh's host addresses.
const meshHosts = "{ 10.62.0.0/16, 10.63.0.0/16 }"
const silosAll = "10.64.0.0/16"

// servicesAll is where Services' virtual IPs are (v1.ServiceCIDR).
const servicesAll = "10.65.0.0/16"

// pick sends to one of targets, chosen at random per connection.
func pick(ts []Target) string {
	if len(ts) == 1 {
		return fmt.Sprintf("dnat ip to %s:%d", ts[0].IP, ts[0].Port)
	}
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = fmt.Sprintf("%d : %s . %d", i, t.IP, t.Port)
	}
	return fmt.Sprintf("dnat ip to numgen random mod %d map { %s }", len(ts), strings.Join(parts, ", "))
}

type rule struct {
	name  string
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
			out = append(out, rule{p.Name, protoOf(p), p.Port})
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

// cutRules end the connections an outside rule let in to a silo's port, once that rule is gone (a
// lease ended): both directions of a translated connection whose original destination matched
// (orig: its public address, or the node port), placed before the rules that let established
// traffic through. TCP is reset, so both ends learn at once; UDP is dropped. Connections to the
// same port that weren't translated (silo to silo, allowFrom) are untouched. They're harmless while
// the port stays closed (nothing new is translated) and go when it opens again.
func cutRules(bridge string, ip netip.Addr, proto string, port int, orig string) []string {
	verdict := "drop"
	if proto == "tcp" {
		verdict = "reject with tcp reset"
	}
	return []string{
		fmt.Sprintf("oifname %q ip daddr %s %s dport %d ct status dnat %s %s", bridge, ip, proto, port, orig, verdict),
		fmt.Sprintf("iifname %q ip saddr %s %s sport %d ct status dnat %s %s", bridge, ip, proto, port, orig, verdict),
	}
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
	var redirect, dnat, snat, fwd, br, egress, cut []string
	for _, s := range local {
		if !s.IP.IsValid() {
			continue
		}
		// Exposure: DNAT from its public address, then let through only the allowed sources.
		exp, from := Exposed(s.Spec)
		if s.PublicIP.IsValid() {
			for _, r := range exp {
				sources := from
				if contains(s.Leased, r.name) && s.LeaseFrom != nil {
					sources = s.LeaseFrom
				}
				// Leased with no lease now (or a lease no source may use): no rule; cut what a
				// lease let in.
				if contains(s.Closed, r.name) || (sources != nil && len(sources) == 0) {
					cut = append(cut, cutRules(h.Bridge, s.IP, r.proto, r.port, fmt.Sprintf("ct original ip daddr %s", s.PublicIP))...)
					continue
				}
				dnat = append(dnat, fmt.Sprintf("ip daddr %s %s dport %d dnat ip to %s:%d", s.PublicIP, r.proto, r.port, s.IP, r.port))
				src := ""
				if len(sources) > 0 {
					src = "ip saddr " + set(sources) + " "
				}
				fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d ct status dnat accept", h.Bridge, s.IP, src, r.proto, r.port))
			}
		}
		// From a plugin's load balancer: its node ports, from its addresses only.
		if len(s.NodePorts) > 0 && len(s.SourceRanges) > 0 {
			protos := map[string]string{}
			if s.Spec.Service != nil {
				for _, p := range s.Spec.Service.Ports {
					protos[p.Name] = protoOf(p)
				}
			}
			src := "ip saddr " + set(s.SourceRanges) + " "
			for _, np := range s.NodePorts {
				proto := protos[np.Name]
				if proto == "" {
					continue
				}
				if contains(s.Closed, np.Name) {
					cut = append(cut, cutRules(h.Bridge, s.IP, proto, np.Port, fmt.Sprintf("ct original proto-dst %d", np.NodePort))...)
					continue
				}
				dnat = append(dnat, fmt.Sprintf("%s%s dport %d dnat ip to %s:%d", src, proto, np.NodePort, s.IP, np.Port))
				fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d ct status dnat accept", h.Bridge, s.IP, src, proto, np.Port))
			}
		}
		// To the egress gate: its TLS by host name, to outside the cluster.
		if h.GatePort > 0 && len(s.GatePorts) > 0 {
			ps := make([]string, len(s.GatePorts))
			for i, p := range s.GatePorts {
				ps[i] = p.String()
			}
			redirect = append(redirect, fmt.Sprintf("iifname %q ip saddr %s ip daddr != { %s, %s, 10.62.0.0/16, 10.63.0.0/16 } tcp dport %s redirect to :%d",
				h.Bridge, s.IP, silosAll, servicesAll, set(ps), h.GatePort))
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
					br = append(br, m) // same host: bridged…
					// …or routed, when it came through a Service's virtual IP
					fwd = append(fwd, fmt.Sprintf("oifname %q %s", h.Bridge, strings.Replace(m, " accept", " ct status dnat accept", 1)))
				} else {
					fwd = append(fwd, fmt.Sprintf("oifname %q %s", h.Bridge, m)) // across the mesh: routed
				}
			}
		}
	}

	// Services: the virtual IP from this host's silos to every endpoint (each endpoint's own host
	// still applies its allowFrom); node ports from the load balancer to the endpoints here.
	svcs := append([]Service(nil), h.Services...)
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Key < svcs[j].Key })
	for _, sv := range svcs {
		for _, p := range sv.Ports {
			if len(p.Targets) == 0 {
				continue
			}
			if sv.ClusterIP.IsValid() {
				dnat = append(dnat, fmt.Sprintf("iifname %q ip daddr %s %s dport %d %s", h.Bridge, sv.ClusterIP, p.Proto, p.Port, pick(p.Targets)))
			}
			var local []Target
			for _, t := range p.Targets {
				if t.Local {
					local = append(local, t)
				}
			}
			if p.NodePort == 0 || len(local) == 0 || len(sv.SourceRanges) == 0 {
				continue
			}
			src := "ip saddr " + set(sv.SourceRanges) + " "
			dnat = append(dnat, fmt.Sprintf("%s%s dport %d %s", src, p.Proto, p.NodePort, pick(local)))
			for _, t := range local {
				fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d ct status dnat accept", h.Bridge, t.IP, src, p.Proto, t.Port))
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
	for _, r := range redirect {
		w("    %s", r)
	}
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
	// Hairpin: a silo reaching one on this host through an address that was translated (a
	// Service's virtual IP, an exposed port): without this the reply would go straight across the
	// bridge and skip the translation back. allowFrom was checked in forward, on the real source.
	w("    ip saddr %s ip daddr %s oifname %q ct status dnat masquerade", h.Subnet, h.Subnet, h.Bridge)
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
	w("    iifname %q ip daddr %s drop", h.Bridge, meshHosts)
	for _, r := range cut {
		w("    %s", r)
	}
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
	if h.Endpoint.IsValid() { // the local endpoint is the bridge's only: never from the mesh or the uplink
		w("    iifname != %q ip daddr %s drop", h.Bridge, h.Endpoint)
	}
	w("    iifname %q ct state established,related accept", h.Bridge)
	w("    iifname %q ip daddr %s udp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s tcp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s icmp type echo-request accept", h.Bridge, h.Gateway)
	if h.GatePort > 0 && len(redirect) > 0 {
		w("    iifname %q ip daddr %s tcp dport %d accept", h.Bridge, h.Gateway, h.GatePort)
	}
	if h.Endpoint.IsValid() {
		for _, s := range local {
			if s.Endpoint && s.IP.IsValid() {
				w("    iifname %q ip saddr %s ip daddr %s tcp dport 80 accept", h.Bridge, s.IP, h.Endpoint)
			}
		}
	}
	w("    iifname %q drop", h.Bridge)
	w("  }")
	w("}")
	w("table bridge kevaso")
	w("delete table bridge kevaso")
	w("table bridge kevaso {")
	// Prerouting, not forward: frames for the host itself (its DNS, the egress gate, the local
	// endpoint, ARP to it) never cross forward, and the host tells silos apart by these addresses.
	w("  chain prerouting {")
	w("    type filter hook prerouting priority filter; policy accept;")
	for _, s := range local {
		if s.Tap != "" && s.IP.IsValid() {
			w("    iifname %q ip saddr != %s drop", s.Tap, s.IP)     // no silo speaks for another…
			w("    iifname %q arp saddr ip != %s drop", s.Tap, s.IP) // …nor claims its address
		}
	}
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
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
