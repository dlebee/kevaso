// Package kni is the built-in silo networking on a worker (design §7: KNI "bridge"): the host's
// nftables rules for its silos, generated from the API, applied atomically. Pure here; Apply runs
// nft.
//
// Default deny, as the design's table says: no silo reaches another silo's ports (on this host or
// across the mesh) unless the receiving silo's service port names it in allowFrom; nothing outside
// reaches a silo unless a service port opens on the host (hostPort) or a load balancer; a silo reaches nothing
// outside the cluster unless one of its
// Grants opens it (raw TCP/UDP to a CIDR here; host names through the egress gate); silos can't
// reach the mesh's host addresses, nor their own host beyond DNS, ping and, for a silo whose grants
// need one, its local endpoint (ADR 0009). A silo also reaches no host's own address on the silo
// network (10.64.N.1), on this host or another, and a packet that arrives over the mesh from a
// silo reaches nothing of this host. Exposed ports are DNAT (the client's address is kept: E009), and a silo's
// outbound source is SNAT to its service's or its pool's address when it asks.
package kni

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	v1 "kevaso.com/core/api/v1"
)

// Silo is what the rules need about one silo.
type Silo struct {
	Key string // namespace/name
	IP  netip.Addr
	Tap string // its tap device on the bridge (local silos only)
	// MAC is the source MAC its runtime fixed for that tap ("": not fixed; the address alone is
	// bound then).
	MAC  string
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
	// Endpoint: the silo reaches its host's local endpoint (Host.Endpoint, port 80).
	Endpoint bool
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
	// HostPortsRefused: the controller's HostPorts condition is False. Another silo holds a host
	// port this one asks for, so none of its host-port rules are emitted. A load balancer it has
	// is unaffected. The zero value emits rules, which is what a silo with no such condition does.
	HostPortsRefused bool
	// Paths are extra silo-to-silo openings (an Ingress's controller to its target's port), as if
	// that port's allowFrom named them: port name → callers (NAMESPACE/NAME).
	Paths map[string][]string
}

// Binding is one bridge port and the only source it may send from.
type Binding struct {
	Tap string
	IP  netip.Addr
	MAC string // normalized; "": the address alone
}

// Bindings are the ports of the local silos and the address (and MAC) each may send from: only
// silos with a tap whose name and address the rules can write (an IPv4 address; a MAC that parses),
// one binding per tap and per address. Anything else binds nothing, so that port stays closed.
func Bindings(local []Silo) []Binding {
	var out []Binding
	taps, ips := map[string]int{}, map[netip.Addr]int{}
	for _, s := range local {
		if !s.IP.Is4() || !validIfname(s.Tap) {
			continue
		}
		b := Binding{Tap: s.Tap, IP: s.IP}
		if s.MAC != "" {
			m, err := net.ParseMAC(s.MAC)
			if err != nil || len(m) != 6 {
				continue // a MAC we can't write: the port stays closed rather than unbound
			}
			b.MAC = m.String()
		}
		taps[b.Tap]++
		ips[b.IP]++
		out = append(out, b)
	}
	// Two silos claiming one tap or one address: neither is bound (one of them is stale, and the
	// rules can't tell which).
	var keep []Binding
	for _, b := range out {
		if taps[b.Tap] == 1 && ips[b.IP] == 1 {
			keep = append(keep, b)
		}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Tap < keep[j].Tap })
	return keep
}

// validIfname: a Linux interface name nft can take quoted (1-15 bytes, none of them a quote,
// space, slash or control character).
func validIfname(n string) bool {
	if n == "" || len(n) > 15 {
		return false
	}
	for _, c := range []byte(n) {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
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
	// Endpoint is the silos' local endpoint's address on the bridge (invalid: none): reached on
	// port 80 from the bridge only, by the silos that have one.
	Endpoint netip.Addr
	// Services are the cluster's standalone Services with endpoints.
	Services []Service
	// Reserved: host-port numbers this host listens on beyond ReservedHostPort, and why. A silo's
	// host-port DNAT for one of them is left out. Nil means this host adds none.
	Reserved map[int]string
	// Revoke is the grants and allowFrom entries previously loaded (nil on the first load). A flow
	// that was allowed then and is not allowed now is reset, the same way a lease's connections
	// are when the lease ends. Flows that are still allowed are not.
	Revoke *Host
}

// Prefixes no silo may reach directly: the mesh's host addresses.
const meshHosts = "{ 10.62.0.0/16, 10.63.0.0/16 }"
const silosAll = "10.64.0.0/16"

// MeshDevices are the mesh's interfaces (internal/mesh's Outer and Inner): the only way a silo on
// another host reaches this one.
var MeshDevices = []string{"kevaso0", "kevaso1"}

// servicesAll is where Services' virtual IPs are (v1.ServiceCIDR).
const servicesAll = "10.65.0.0/16"

// closedRangeDrops refuses silo egress to every IPv4 range a grant never opens, before any
// per-grant accept. Link-local 169.254/16 is one of those ranges.
func closedRangeDrops(h Host) []string {
	var pfx []string
	for _, p := range v1.ClosedPrefixes() {
		if p.Addr().Is4() {
			pfx = append(pfx, p.String())
		}
	}
	if len(pfx) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("iifname %q ip daddr { %s } drop", h.Bridge, strings.Join(pfx, ", "))}
}

// hostAddressDrops refuses silo egress to this host's own addresses. A wide grant does not
// name them; the same addresses the egress gate keeps off a name (InternalIP, ExternalIP).
func hostAddressDrops(h Host) []string {
	var addrs []string
	seen := map[netip.Addr]bool{}
	for _, a := range []netip.Addr{h.InternalIP, h.ExternalIP} {
		if a.IsValid() && a.Is4() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			addrs = append(addrs, a.String())
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("iifname %q ip daddr { %s } drop", h.Bridge, strings.Join(addrs, ", "))}
}

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
// traffic through. TCP is reset, so both ends learn at once; UDP is dropped. These lease cuts match
// only translated connections. A removed allowFrom entry or grant is cut on its own match, without
// ct status dnat, and only for the flows that entry allowed.
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

// Problem is an entry the rules can't express (K-009, K-036): left out, fail closed (it opens
// nothing; a port whose every source is left out stays closed), and reported to its owner.
type Problem struct {
	Kind   string // Silo | Service | Host
	Owner  string // NAMESPACE/NAME (Silo, Service), or the host's field
	Port   string // the port it was on ("": the silo or service as a whole)
	Entry  string // the entry, quoted (never raw: it goes into status messages)
	Reason string
}

func (p Problem) String() string {
	at := ""
	if p.Port != "" {
		at = "port " + p.Port + ": "
	}
	return at + p.Entry + ": " + p.Reason
}

// gen collects what Generate leaves out.
type gen struct{ problems []Problem }

func (g *gen) bad(kind, owner, port, entry, reason string) {
	g.problems = append(g.problems, Problem{Kind: kind, Owner: owner, Port: port, Entry: strconv.Quote(entry), Reason: reason})
}

// v4Ranges parses a list of IPv4 addresses and prefixes, each written canonically (a prefix with
// host bits set is the network it names). closed: the list had entries and none could be kept,
// so whatever it limits must stay closed (an empty list would mean "from anywhere").
func (g *gen) v4Ranges(kind, owner, port string, items []string) (out []string, closed bool) {
	seen := map[string]bool{}
	for _, it := range items {
		v, why := v4Range(it)
		if why != "" {
			g.bad(kind, owner, port, it, why)
			continue
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, len(items) > 0 && len(out) == 0
}

func v4Range(it string) (string, string) {
	if p, err := netip.ParsePrefix(it); err == nil {
		if !p.Addr().Is4() {
			return "", "an IPv6 range; these rules are IPv4 only"
		}
		return p.Masked().String(), ""
	}
	if a, err := netip.ParseAddr(it); err == nil {
		if !a.Is4() {
			return "", "an IPv6 address; these rules are IPv4 only"
		}
		return a.String(), ""
	}
	return "", "not an IPv4 address or prefix"
}

// v4Addr: a is an IPv4 address the rules can use for what; otherwise it's reported (when set at
// all) and not used.
func (g *gen) v4Addr(kind, owner, port, what string, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if !a.Is4() {
		g.bad(kind, owner, port, a.String(), what+" is not IPv4; these rules are IPv4 only")
		return false
	}
	return true
}

func okPort(n int) bool { return n >= 1 && n <= 65535 }

func okProto(p string) bool { return p == "tcp" || p == "udp" }

// Rules is the host's whole silo ruleset, ready for `nft -f` (it replaces the previous one
// atomically). Deterministic: the same input gives the same text, so unchanged means no reload.
func Rules(h Host) string {
	text, _ := Generate(h)
	return text
}

// Generate is Rules, with what it left out. No rule is built from an unparsed string: every
// address and range is parsed and written canonically where it enters, every port number and
// protocol checked, every interface name whitelisted, so one bad entry (anything that reached the
// store before admission tightened, a plugin's answer) never makes nft refuse the whole table.
func Generate(h Host) (string, []Problem) {
	g := &gen{}
	if !g.v4Addr("Host", "internalIP", "", "the host's internal IP", h.InternalIP) {
		h.InternalIP = netip.Addr{}
	}
	if !g.v4Addr("Host", "externalIP", "", "the host's external IP", h.ExternalIP) {
		h.ExternalIP = netip.Addr{}
	}
	if !h.Endpoint.Is4() {
		h.Endpoint = netip.Addr{}
	}
	if !okPort(h.GatePort) {
		h.GatePort = 0
	}
	var all []Silo
	for _, s := range h.All {
		if s.IP.Is4() { // a caller with an address the rules can't write is "not running" to them
			all = append(all, s)
		}
	}
	h.All = all
	var keep []Silo
	for _, s := range h.Local {
		if s.IP.IsValid() && !s.IP.Is4() {
			g.bad("Silo", s.Key, "", s.IP.String(), "its silo address is not IPv4; its port on the bridge stays closed")
			s.IP = netip.Addr{}
		}
		keep = append(keep, s)
	}
	h.Local = keep
	local := append([]Silo(nil), h.Local...)
	sort.Slice(local, func(i, j int) bool { return local[i].Key < local[j].Key })
	portOwners := hostPortOwners(local, h) // the one silo, if there is exactly one, that may open each host address
	byKey := map[string]Silo{}
	for _, s := range h.All {
		byKey[s.Key] = s
	}
	for _, s := range local {
		byKey[s.Key] = s
	}
	var redirect, dnat, snat, fwd, br, egress, cut, brCut []string
	for _, s := range local {
		if !s.IP.IsValid() {
			continue
		}
		// Outside ports: DNAT from each address the port opens on (the host's internal and/or
		// external IP, its load-balancer address), at its number there (as), then let through
		// only its sources.
		for _, p := range s.Spec.Open() {
			if !okPort(p.Number) || !okPort(p.HostNumber()) || !okProto(lower(p.Protocol)) {
				g.bad("Silo", s.Key, p.Name, fmt.Sprintf("%s %d as %d", p.Protocol, p.Number, p.HostNumber()), "not a port the rules can open")
				continue
			}
			proto, at := lower(p.Protocol), p.HostNumber()
			var ips []string
			hostWhy := ""
			if len(p.HostPort) > 0 && s.HostPortsRefused { // its HostPorts condition is false: it does not hold the port
				hostWhy = "its HostPorts condition is false, so its host ports are not opened"
			} else if len(p.HostPort) > 0 {
				if why := reservedWhy(h, at); why != "" { // a number the platform listens on is not opened, whatever the spec says
					hostWhy = why + ", which a silo may not take"
				}
			}
			if hostWhy != "" {
				g.bad("Silo", s.Key, p.Name, fmt.Sprintf("%s/%d", proto, at), hostWhy)
			}
			for _, n := range p.HostPort {
				if hostWhy != "" {
					break
				}
				a := h.InternalIP
				if n == v1.NetworkExternal {
					a = h.ExternalIP
				}
				if !a.IsValid() {
					continue
				}
				owner, claimed := portOwners[hpKey{a.String(), proto, at}]
				if !claimed || owner != s.Key { // two silos ask and it is not settled which one holds it
					g.bad("Silo", s.Key, p.Name, fmt.Sprintf("%s/%d on %s", proto, at, a), "another silo on this host asks for it and it is not settled which one holds it, so it is not opened")
					continue
				}
				if !contains(ips, a.String()) {
					ips = append(ips, a.String())
				}
			}
			if p.LoadBalancer && g.v4Addr("Silo", s.Key, p.Name, "its load-balancer address", s.LoadBalancerIP) && !contains(ips, s.LoadBalancerIP.String()) {
				ips = append(ips, s.LoadBalancerIP.String())
			}
			if len(ips) == 0 {
				continue
			}
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
			sources, shut := g.v4Ranges("Silo", s.Key, p.Name, p.Sources)
			if shut {
				continue // every source left out: closed, not open to all
			}
			dnat = append(dnat, fmt.Sprintf("ip daddr %s %s dport %d dnat ip to %s:%d", set(ips), proto, at, s.IP, p.Number))
			src := ""
			if len(sources) > 0 {
				src = "ip saddr " + set(sources) + " "
			}
			fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d %s ct status dnat accept", h.Bridge, s.IP, src, proto, p.Number, orig))
		}
		// From a plugin's load balancer: its node ports, from its addresses only.
		ranges, shut := g.v4Ranges("Silo", s.Key, nodePortNames(s.NodePorts), s.SourceRanges)
		if len(s.NodePorts) > 0 && len(ranges) > 0 && !shut {
			protos := map[string]string{}
			for _, p := range s.Spec.Open() {
				if p.LoadBalancer {
					protos[p.Name] = lower(p.Protocol)
				}
			}
			src := "ip saddr " + set(ranges) + " "
			for _, np := range s.NodePorts {
				proto := protos[np.Name]
				if !okProto(proto) {
					continue
				}
				if !okPort(np.Port) || !okPort(np.NodePort) {
					g.bad("Silo", s.Key, np.Name, fmt.Sprintf("%d from node port %d", np.Port, np.NodePort), "not a port the rules can open")
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
		var gatePorts []string
		for _, p := range s.GatePorts {
			if !okPort(p.From) || !okPort(p.To) || p.From > p.To {
				g.bad("Silo", s.Key, "", p.String(), "not a port range its egress gate rule can take")
				continue
			}
			gatePorts = append(gatePorts, p.String())
		}
		if h.GatePort > 0 && len(gatePorts) > 0 {
			ps := gatePorts
			redirect = append(redirect, fmt.Sprintf("iifname %q ip saddr %s ip daddr != { %s, %s, 10.62.0.0/16, 10.63.0.0/16 } tcp dport %s redirect to :%d",
				h.Bridge, s.IP, silosAll, servicesAll, set(ps), h.GatePort))
		}
		// Outbound: only what its grants open.
		for _, e := range s.Egress {
			if !e.Prefix.IsValid() {
				continue
			}
			if !e.Prefix.Addr().Is4() {
				g.bad("Silo", s.Key, "", e.Prefix.String(), "a grant's IPv6 range; these rules are IPv4 only")
				continue
			}
			var ps []string
			for _, p := range e.Ports {
				if !okPort(p.From) || !okPort(p.To) || p.From > p.To {
					g.bad("Silo", s.Key, "", p.String(), "a grant's port range the rules can't take")
					continue
				}
				ps = append(ps, p.String())
			}
			if len(e.Ports) > 0 && len(ps) == 0 {
				continue // every port left out: nothing, not every port
			}
			for _, proto := range e.Protocols {
				if !okProto(proto) {
					g.bad("Silo", s.Key, "", proto, "a grant's protocol the rules can't take")
					continue
				}
				m := fmt.Sprintf("iifname %q ip saddr %s ip daddr %s ", h.Bridge, s.IP, e.Prefix.Masked())
				if len(ps) == 0 {
					egress = append(egress, m+"meta l4proto "+proto+" accept")
					continue
				}
				egress = append(egress, m+proto+" dport "+set(ps)+" accept")
			}
		}
		// Outbound source.
		if g.v4Addr("Silo", s.Key, "", "its egress address", s.EgressIP) {
			snat = append(snat, fmt.Sprintf("ip saddr %s ip daddr != { %s, 10.62.0.0/16, 10.63.0.0/16 } oifname != %q snat ip to %s", s.IP, silosAll, h.Bridge, s.EgressIP))
		}
		// allowFrom: other silos, by their current address, to the port that names them.
		ns := strings.SplitN(s.Key, "/", 2)[0]
		for _, p := range s.Spec.Open() {
			if !okPort(p.Number) || !okProto(lower(p.Protocol)) {
				continue // reported with its outside rules
			}
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
		ranges, shut := g.v4Ranges("Service", sv.Key, "", sv.SourceRanges)
		clusterIP := g.v4Addr("Service", sv.Key, "", "its cluster IP", sv.ClusterIP)
		for _, p := range sv.Ports {
			if !okPort(p.Port) || !okProto(p.Proto) || (p.NodePort != 0 && !okPort(p.NodePort)) {
				g.bad("Service", sv.Key, strconv.Itoa(p.Port), fmt.Sprintf("%s %d node port %d", p.Proto, p.Port, p.NodePort), "not a port the rules can open")
				continue
			}
			var targets []Target
			for _, t := range p.Targets {
				if !t.IP.Is4() || !okPort(t.Port) {
					g.bad("Service", sv.Key, strconv.Itoa(p.Port), netip.AddrPortFrom(t.IP, uint16(max(0, min(t.Port, 65535)))).String(), "an endpoint the rules can't send to (IPv4 only)")
					continue
				}
				targets = append(targets, t)
			}
			if len(targets) == 0 {
				continue
			}
			if clusterIP {
				dnat = append(dnat, fmt.Sprintf("iifname %q ip daddr %s %s dport %d %s", h.Bridge, sv.ClusterIP, p.Proto, p.Port, pick(targets)))
			}
			var local []Target
			for _, t := range targets {
				if t.Local {
					local = append(local, t)
				}
			}
			if p.NodePort == 0 || len(local) == 0 || len(ranges) == 0 || shut {
				continue
			}
			src := "ip saddr " + set(ranges) + " "
			dnat = append(dnat, fmt.Sprintf("%s%s dport %d %s", src, p.Proto, p.NodePort, pick(local)))
			for _, t := range local {
				fwd = append(fwd, fmt.Sprintf("oifname %q ip daddr %s %s%s dport %d ct status dnat accept", h.Bridge, t.IP, src, p.Proto, t.Port))
			}
		}
	}

	if h.Revoke != nil {
		inet, bridge := revokeCuts(h, *h.Revoke)
		cut = append(cut, inet...)
		brCut = append(brCut, bridge...)
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
	// A silo's address comes from the bridge (this host's silos) or the mesh (the others'), never
	// from the uplink: allowFrom trusts the source address, so a spoofed one stops here.
	w("    oifname %q ip saddr %s iifname != { %q, %q, %q } drop", h.Bridge, silosAll, h.Bridge, MeshDevices[0], MeshDevices[1])
	for _, r := range cut {
		w("    %s", r)
	}
	w("    oifname %q ct state established,related accept", h.Bridge)
	for _, r := range fwd {
		w("    %s", r)
	}
	w("    oifname %q drop", h.Bridge)
	// From silos: replies, then never a host's own address on the silo network (10.64.N.1, here or
	// on another host), then other silos (their host decides), then grants only.
	w("    iifname %q ct state established,related accept", h.Bridge)
	w("    iifname %q ip daddr %s drop", h.Bridge, siloGatewaySet()) // a silo reaches no host's own address on the silo network
	w("    iifname %q ip daddr %s accept", h.Bridge, silosAll)
	// A grant's accept can be as wide as 0.0.0.0/0. These drops are first, so that still means
	// the internet: not a closed range, not link-local, not this host's own addresses. Silo
	// traffic was accepted on the line above; Services are already translated to a silo address.
	for _, r := range closedRangeDrops(h) { // a grant never reaches a closed range
		w("    %s", r)
	}
	for _, r := range hostAddressDrops(h) { // a grant never reaches this host's own addresses
		w("    %s", r)
	}
	for _, r := range egress {
		w("    %s", r)
	}
	w("    iifname %q drop", h.Bridge)
	w("  }")
	w("  chain input {")
	w("    type filter hook input priority filter; policy accept;")
	w("    iifname { %q, %q } ip saddr %s ct state established,related accept", MeshDevices[0], MeshDevices[1], silosAll)
	w("    iifname { %q, %q } ip saddr %s drop", MeshDevices[0], MeshDevices[1], silosAll) // a silo on another host reaches nothing of this one
	if h.Endpoint.IsValid() {                                                              // the local endpoint is the bridge's only: never from the mesh or the uplink
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
	// Default deny per port: a port passes only its own silo's IPv4 address (and the MAC its
	// runtime fixed), as IP or ARP; any other source, IPv6, any other ether type, and every frame
	// from a port whose silo has no address yet or that these rules don't know, are dropped. Frames
	// the host itself sends onto the bridge don't pass this hook.
	w("  chain prerouting {")
	w("    type filter hook prerouting priority filter; policy drop;")
	for _, b := range Bindings(local) {
		e := ""
		if b.MAC != "" {
			e = "ether saddr " + b.MAC + " "
		}
		w("    iifname %q %sip saddr %s accept", b.Tap, e, b.IP) // no silo speaks for another…
		ae := ""
		if b.MAC != "" {
			ae = " arp saddr ether " + b.MAC
		}
		w("    iifname %q %sarp saddr ip %s%s accept", b.Tap, e, b.IP, ae) // …nor claims its address
	}
	w("  }")
	w("  chain forward {")
	w("    type filter hook forward priority filter; policy accept;")
	w("    ether type arp accept") // silos must find each other's MAC before allowFrom can matter
	for _, r := range brCut {      // a same-host allowFrom flow, before established keeps it
		w("    %s", r)
	}
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
	return b.String(), g.problems
}

// nodePortNames is the port the node-port rules belong to, for a report ("" when several).
func nodePortNames(nps []v1.NodePort) string {
	if len(nps) == 1 {
		return nps[0].Name
	}
	var names []string
	for _, np := range nps {
		names = append(names, np.Name)
	}
	return strings.Join(names, ",")
}
