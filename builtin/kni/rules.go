// Package kni is the built-in silo networking on a worker (design §7: KNI "bridge"): the host's
// nftables rules for its silos, generated from the API, applied atomically. Pure here; Apply runs
// nft.
//
// Default deny, as the design's table says: no silo reaches another silo's ports (on this host or
// across the mesh) unless the receiving silo's service port names it in allowFrom; nothing outside
// reaches a silo unless a service port opens on the host (hostPort) or a load balancer; a silo reaches nothing outside the cluster unless one of its
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
	// LoadBalancerIP is the address its loadBalancer ports are reached on when it's on this host
	// (ip-pool, an announced shared IP); EgressIP where its traffic leaves from ("" = the host
	// default).
	LoadBalancerIP netip.Addr
	EgressIP       netip.Addr
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
	// Leases (design §7.2d): Leased are the outside ports (by name) that open only on a lease, and
	// Closed those of them with no active lease now: a closed port has no outside rule at all, and
	// connections that a lease let in are cut (reset) once it ends. Silo-to-silo access
	// (allowFrom) is never leased.
	Leased []string
	Closed []string
	// Held (design §0.6): its service's routeWhen holds traffic back now (ready, and it isn't).
	// Its outside ports and node ports get no rule, as if closed, but nothing is cut: connections
	// it has stay (a lease is access, readiness is load). allowFrom stays too: the name is held
	// where names are answered (no address).
	Held bool
	// Paths are extra silo-to-silo openings (an Ingress's controller to its target's port), as if
	// that port's allowFrom named them: port name → callers (NAMESPACE/NAME).
	Paths map[string][]string
}

// Outside is what one outside port's rule is now: open (a rule) only when its lease, if
// it's leased, is open and its routing isn't held; cut (end what a lease let in) only when its
// lease is closed. The two decisions stay apart: either one closes it.
func Outside(s Silo, port string) (open, cut bool) {
	if contains(s.Closed, port) {
		return false, true
	}
	return !s.Held, false
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
	// InternalIP and ExternalIP are the host's addresses (design §7.0; invalid: it has none
	// there). A host port opens on the ones its service port asks for.
	InternalIP netip.Addr
	ExternalIP netip.Addr
	Local      []Silo // silos on this host
	All        []Silo // every silo in the cluster with an address, to resolve allowFrom sources
	// GatePort is where the egress gate listens on the gateway (0: no gate).
	GatePort int
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

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func lower(proto string) string { return strings.ToLower(proto) }

func set(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "{ " + strings.Join(items, ", ") + " }"
}

// cutRules end the connections an outside rule let in to a silo's port, once that rule is gone (a
// lease ended): both directions of a translated connection whose original destination matched
// (orig: the host's or load balancer's address, or the node port), placed before the rules that let established
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
		// Outside ports: DNAT from each address the port opens on (the host's internal and/or
		// external IP, its load-balancer address), at its number there (as), then let through
		// only its sources.
		for _, p := range s.Spec.Open() {
			var ips []string
			for _, n := range p.HostPort {
				a := h.InternalIP
				if n == v1.NetworkExternal {
					a = h.ExternalIP
				}
				if a.IsValid() && !contains(ips, a.String()) {
					ips = append(ips, a.String())
				}
			}
			if p.LoadBalancer && s.LoadBalancerIP.IsValid() && !contains(ips, s.LoadBalancerIP.String()) {
				ips = append(ips, s.LoadBalancerIP.String())
			}
			if len(ips) == 0 {
				continue
			}
			proto, at := lower(p.Protocol), p.HostNumber()
			orig := "ct original ip daddr " + set(ips)
			// Leased with no lease now: no rule; cut what a lease let in. Held by routing: no
			// rule, nothing cut.
			open, closed := Outside(s, p.Name)
			if closed {
				cut = append(cut, cutRules(h.Bridge, s.IP, proto, p.Number, orig)...)
				continue
			}
			if !open {
				continue
			}
			dnat = append(dnat, fmt.Sprintf("ip daddr %s %s dport %d dnat ip to %s:%d", set(ips), proto, at, s.IP, p.Number))
			src := ""
			if len(p.Sources) > 0 {
				src = "ip saddr " + set(p.Sources) + " "
			}
			fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d %s ct status dnat accept", h.Bridge, s.IP, src, proto, p.Number, orig))
		}
		// From a plugin's load balancer: its node ports, from its addresses only.
		if len(s.NodePorts) > 0 && len(s.SourceRanges) > 0 {
			protos := map[string]string{}
			for _, p := range s.Spec.Open() {
				if p.LoadBalancer {
					protos[p.Name] = lower(p.Protocol)
				}
			}
			src := "ip saddr " + set(s.SourceRanges) + " "
			for _, np := range s.NodePorts {
				proto := protos[np.Name]
				if proto == "" {
					continue
				}
				open, closed := Outside(s, np.Name)
				if closed {
					cut = append(cut, cutRules(h.Bridge, s.IP, proto, np.Port, fmt.Sprintf("ct original proto-dst %d", np.NodePort))...)
					continue
				}
				if !open {
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
		// allowFrom: other silos, by their current address, to the port that names them.
		ns := strings.SplitN(s.Key, "/", 2)[0]
		for _, p := range s.Spec.Open() {
			callers := append(append([]string(nil), p.AllowFrom...), s.Paths[p.Name]...)
			seen := map[string]bool{}
			for _, key := range callers {
				if !strings.Contains(key, "/") {
					key = ns + "/" + key
				}
				src, ok := byKey[key]
				if seen[key] || !ok || !src.IP.IsValid() {
					continue // not running anywhere right now: nothing to open
				}
				seen[key] = true
				m := fmt.Sprintf("ip saddr %s ip daddr %s %s dport %d accept", src.IP, s.IP, lower(p.Protocol), p.Number)
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
	w("    iifname %q ct state established,related accept", h.Bridge)
	w("    iifname %q ip daddr %s udp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s tcp dport 53 accept", h.Bridge, h.Gateway)
	w("    iifname %q ip daddr %s icmp type echo-request accept", h.Bridge, h.Gateway)
	if h.GatePort > 0 && len(redirect) > 0 {
		w("    iifname %q ip daddr %s tcp dport %d accept", h.Bridge, h.Gateway, h.GatePort)
	}
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
