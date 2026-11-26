package v1

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Ports and services (design §7.0, networking v2): a silo declares its ports (spec.ports); its
// services (spec.services) are what make any of them reachable, each one way in: Internal (silos
// in allowFrom, over the mesh), HostPort (at the worker running it: its main IP, a kept IP, or a
// SiloSet instance's own) or LoadBalancer (a provider's balancer in front). A silo without a
// service has a silo IP for its own traffic, no name, and nothing reachable.

// Networks (design §7.0): where an address is. A host has an internal and/or an external IP and a
// mesh IP; a service's name answers on each (SERVICE.NAMESPACE.NETWORK.kevaso), and a host port
// opens on internal and/or external. They're also the names no namespace may take.
const (
	NetworkMesh     = "mesh"
	NetworkInternal = "internal"
	NetworkExternal = "external"
)

// DefaultSuffix is the names' last label unless the cluster sets another (design §7.0).
const DefaultSuffix = "kevaso"

// ServiceDNSName is SERVICE.NAMESPACE[.NETWORK].SUFFIX (suffix "": the default).
func ServiceDNSName(service, namespace, network, suffix string) string {
	if suffix == "" {
		suffix = DefaultSuffix
	}
	n := service + "." + namespace
	if network != "" {
		n += "." + network
	}
	return n + "." + suffix
}

// Networks are the three, in the order names list them.
var Networks = []string{NetworkMesh, NetworkInternal, NetworkExternal}

// Service types (networking v2): each service is one way in.
const (
	ServiceInternal     = "Internal"     // the default: silos in allowFrom, over the mesh
	ServiceHostPort     = "HostPort"     // traffic arrives at the worker running the silo (Kubernetes hostPort)
	ServiceLoadBalancer = "LoadBalancer" // a provider's balancer in front
)

// SiloPort is one port a silo declares: what exists. An undeclared port can never be reached.
type SiloPort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // TCP (default) | UDP
}

// Proto is the port's protocol, TCP or UDP.
func (p SiloPort) Proto() string {
	if strings.EqualFold(p.Protocol, "UDP") {
		return "UDP"
	}
	return "TCP"
}

// SiloService is one of a silo's services: one way in (its type) to some of its declared ports.
// A silo may have several, each its own name; a port may be in several.
type SiloService struct {
	// Name is what others resolve (NAME.NAMESPACE[.NETWORK].kevaso); default: the silo's name.
	// Unique in the namespace, across silos' services and standalone Services. In a SiloSet's
	// template, an instance's service is the instance's name (unnamed) or INSTANCE-NAME.
	Name string `json:"name,omitempty"`
	// Type is the way in: Internal (default), HostPort or LoadBalancer.
	Type  string        `json:"type,omitempty"`
	Ports []ServicePort `json:"ports,omitempty"`
	// HostPort says which address a HostPort service arrives on: exactly one of worker, ip, own.
	// Absent: { worker: external }. Only with type HostPort.
	HostPort *HostPortSource `json:"hostPort,omitempty"`
	// LoadBalancer is the provider whose balancer fronts it. Required with type LoadBalancer,
	// refused otherwise.
	LoadBalancer *LoadBalancerSpec `json:"loadBalancer,omitempty"`
	// Annotations tune the way in: a provider's, declared by its plugin and checked at apply
	// (e.g. linode.kevaso.com/nodebalancer: edge shares one balancer).
	Annotations map[string]string `json:"annotations,omitempty"`
	// RouteWhen: ready (traffic only while the readiness probe passes) or running (as soon as the
	// silo runs). Required with a readiness probe; without one it's running (design §0.6).
	RouteWhen string `json:"routeWhen,omitempty"`
}

// TypeOrDefault is the service's type, Internal when it says none.
func (sv SiloService) TypeOrDefault() string {
	if sv.Type == "" {
		return ServiceInternal
	}
	return sv.Type
}

// Way is where a HostPort service arrives: its hostPort, or { worker: external } when it says
// none. The zero value for any other type.
func (sv SiloService) Way() HostPortSource {
	if sv.TypeOrDefault() != ServiceHostPort {
		return HostPortSource{}
	}
	if sv.HostPort == nil {
		return HostPortSource{Worker: NetworkExternal}
	}
	return *sv.HostPort
}

// HostPortSource is the address a HostPort service arrives on: exactly one of them.
type HostPortSource struct {
	// Worker: the main IP of the worker running the silo, external or internal. The address
	// changes with the worker, so the silo can run anywhere.
	Worker string `json:"worker,omitempty"`
	// IP names an IP in this namespace: a host's address (pinned to that host) or a provider's
	// (within its reach).
	IP string `json:"ip,omitempty"`
	// Own: a SiloSet instance's own member of the set's IPSet (spec.ips), by ordinal.
	Own bool `json:"own,omitempty"`
}

// Ways is how many of worker, ip and own are set (exactly one is right).
func (h HostPortSource) Ways() int {
	n := 0
	for _, b := range []bool{h.Worker != "", h.IP != "", h.Own} {
		if b {
			n++
		}
	}
	return n
}

// String is the way as a person writes it: worker: external, ip: NAME, own.
func (h HostPortSource) String() string {
	switch {
	case h.IP != "":
		return "ip: " + h.IP
	case h.Own:
		return "own"
	case h.Worker != "":
		return "worker: " + h.Worker
	}
	return ""
}

// LoadBalancerSpec is the balancer in front of a LoadBalancer service.
type LoadBalancerSpec struct {
	// Provider is the installed provider (a plugin's name, e.g. linode) that makes the balancer.
	Provider string `json:"provider"`
	// IP names a kept IP (type Provider) the balancer answers on, only where the provider lets a
	// kept IP front a balancer (a Linode NodeBalancer has its own address: refused there).
	IP string `json:"ip,omitempty"`
}

// ServicePort opens one declared port in a service.
type ServicePort struct {
	Port string `json:"port"` // a declared port's name (spec.ports)
	// AllowFrom are the silos that may connect to it on its silo IP: NAME (this namespace) or
	// NAMESPACE/NAME. It works with every type.
	AllowFrom []string `json:"allowFrom,omitempty"`
	// As is the number on the host or the load balancer (default: the declared port's). Not on
	// Internal.
	As int `json:"as,omitempty"`
	// Sources are the network ranges (CIDRs) that may connect on the host or the load balancer;
	// absent: anyone who can reach that address. Not on Internal.
	Sources []string `json:"sources,omitempty"`
	// Lease: the port opens on the host only on a lease, on its own terms (design §7.2d). HostPort
	// only.
	Lease *PortLease `json:"lease,omitempty"`
}

// OpenPort is a service port with the declared port it names and the service it's in.
type OpenPort struct {
	ServicePort
	Service  string // the service's name (ServiceNameOf)
	Type     string // the service's type
	Way      HostPortSource
	Name     string // the declared port's name
	Number   int    // its number in the silo
	Protocol string // TCP | UDP
	// HostPort is the worker network it opens on (internal or external), for a HostPort service
	// on the worker's address; empty otherwise. A port on an IP (Way ip, own) opens on that IP's
	// address instead, which the worker reads from the IP while the silo holds it there.
	HostPort []string
	// LoadBalancer: the port is on the service's balancer.
	LoadBalancer bool
}

// Outside says whether the port opens anywhere but its silo IP: on the host, or a load balancer.
func (p OpenPort) Outside() bool { return p.Type == ServiceHostPort || p.Type == ServiceLoadBalancer }

// On says whether the port opens on the worker's address on network (internal | external).
func (p OpenPort) On(network string) bool { return slices.Contains(p.HostPort, network) }

// HostNumber is the port's number on the host or the load balancer (as, or its own).
func (p OpenPort) HostNumber() int {
	if p.As > 0 {
		return p.As
	}
	return p.Number
}

// Declared is the silo's declared port named name.
func (s SiloSpec) Declared(name string) (SiloPort, bool) {
	for _, p := range s.Ports {
		if p.Name == name {
			return p, true
		}
	}
	return SiloPort{}, false
}

// ServiceNameOf is a service's name in a silo named silo: its own, or the silo's.
func ServiceNameOf(sv SiloService, silo string) string {
	if sv.Name != "" {
		return sv.Name
	}
	return silo
}

// OpenIn are the ports of the silo's services, each with its declared port and its service, in
// the services' order; a service port naming no declared port is left out (admission refuses it).
// A port in several services is there once per service. silo names unnamed services.
func (s SiloSpec) OpenIn(silo string) []OpenPort {
	var out []OpenPort
	for _, sv := range s.Services {
		t := sv.TypeOrDefault()
		way := sv.Way()
		for _, sp := range sv.Ports {
			d, ok := s.Declared(sp.Port)
			if !ok {
				continue
			}
			op := OpenPort{ServicePort: sp, Service: ServiceNameOf(sv, silo), Type: t, Way: way, Name: d.Name, Number: d.Port, Protocol: d.Proto()}
			if way.Worker != "" {
				op.HostPort = []string{way.Worker}
			}
			op.LoadBalancer = t == ServiceLoadBalancer
			out = append(out, op)
		}
	}
	return out
}

// Open is OpenIn with services unnamed left unnamed (callers that don't need the names).
func (s SiloSpec) Open() []OpenPort { return s.OpenIn("") }

// OpenPort is the first service port opening the declared port name (ok false: no service does).
func (s SiloSpec) OpenPort(name string) (OpenPort, bool) {
	for _, p := range s.Open() {
		if p.Name == name {
			return p, true
		}
	}
	return OpenPort{}, false
}

// LeasedPort is the first service port that opens the declared port name outside on a lease
// (ok false: none does). A port may be in several services, say an Internal one for other silos
// and a HostPort one on a lease: OpenPort is the first, which may not be the leased one.
func (s SiloSpec) LeasedPort(name string) (OpenPort, bool) {
	for _, p := range s.Open() {
		if p.Name == name && p.Lease != nil && p.Outside() {
			return p, true
		}
	}
	return OpenPort{}, false
}

// LoadBalanced says whether any of its services is a LoadBalancer.
func (s SiloSpec) LoadBalanced() bool {
	return slices.ContainsFunc(s.Services, func(sv SiloService) bool { return sv.TypeOrDefault() == ServiceLoadBalancer })
}

// OnHost says whether any of its services is a HostPort.
func (s SiloSpec) OnHost() bool {
	return slices.ContainsFunc(s.Services, func(sv SiloService) bool { return sv.TypeOrDefault() == ServiceHostPort })
}

// Balancers are its LoadBalancer services.
func (s SiloSpec) Balancers() []SiloService {
	var out []SiloService
	for _, sv := range s.Services {
		if sv.TypeOrDefault() == ServiceLoadBalancer {
			out = append(out, sv)
		}
	}
	return out
}

// RouteWhen is the first routeWhen its services state (each service routes by its own: see
// internal/routing).
func (s SiloSpec) RouteWhen() string {
	for _, sv := range s.Services {
		if sv.RouteWhen != "" {
			return sv.RouteWhen
		}
	}
	return ""
}

// UsesOwn says whether the spec takes a SiloSet instance's own IPSet member (hostPort own or
// egress own).
func (s SiloSpec) UsesOwn() bool {
	if src := s.Network.Egress.Source; src != nil && src.Own {
		return true
	}
	return slices.ContainsFunc(s.Services, func(sv SiloService) bool { return sv.HostPort != nil && sv.HostPort.Own })
}

// NamedIPs are the IPs the spec names, each once, with the field naming it first: hostPort.ip,
// loadBalancer.ip, egress.source.ip.
func (s SiloSpec) NamedIPs() []NamedIP {
	var out []NamedIP
	add := func(name, field string) {
		if name == "" || slices.ContainsFunc(out, func(n NamedIP) bool { return n.Name == name }) {
			return
		}
		out = append(out, NamedIP{Name: name, Field: field})
	}
	for i, sv := range s.Services {
		if sv.HostPort != nil {
			add(sv.HostPort.IP, fmt.Sprintf("services[%d].hostPort.ip", i))
		}
		if sv.LoadBalancer != nil {
			add(sv.LoadBalancer.IP, fmt.Sprintf("services[%d].loadBalancer.ip", i))
		}
	}
	if src := s.Network.Egress.Source; src != nil {
		add(src.IP, "network.egress.source.ip")
	}
	return out
}

// NamedIP is an IP a spec names, and where.
type NamedIP struct {
	Name, Field string
}

// ServiceNames are the silo's services' names, in order; none for a silo without a service,
// which has no name.
func ServiceNames(s *Silo) []string {
	var out []string
	for _, sv := range s.Spec.Services {
		out = append(out, ServiceNameOf(sv, s.Name))
	}
	return out
}

// ServiceName is the silo's first service's name ("" without a service).
// TODO(net-v2 wave 2): callers that show one name should show every service's.
func ServiceName(s *Silo) string {
	if n := ServiceNames(s); len(n) > 0 {
		return n[0]
	}
	return ""
}

// AllowedFrom says whether the silo caller (namespace/name) may connect to port on s, by the
// allowFrom of any of s's services that opens it.
func AllowedFrom(s *Silo, port, caller string) bool {
	for _, p := range s.Spec.Open() {
		if p.Name != port {
			continue
		}
		for _, a := range p.AllowFrom {
			key := a
			if !strings.Contains(key, "/") {
				key = s.Namespace + "/" + key
			}
			if key == caller {
				return true
			}
		}
	}
	return false
}

// SiloNetwork is a silo's outbound choices.
type SiloNetwork struct {
	Egress Egress `json:"egress,omitempty"`
}

// Egress picks the source address.
type Egress struct {
	// Source is the address its traffic leaves from. Absent: the worker's own IP.
	Source *EgressSource `json:"source,omitempty"`
}

// EgressSource is a silo's address out: exactly one of them.
type EgressSource struct {
	IP  string `json:"ip,omitempty"`  // an IP in this namespace (out from the same IP it receives on)
	Own bool   `json:"own,omitempty"` // a SiloSet instance's own IPSet member
}

// Ways is how many of ip and own are set (exactly one is right).
func (e EgressSource) Ways() int {
	n := 0
	if e.IP != "" {
		n++
	}
	if e.Own {
		n++
	}
	return n
}

// SiloServiceStatus says where the service is reachable, port by port, and where its traffic
// comes from (design §7.0: "what the status shows").
type SiloServiceStatus struct {
	Name string `json:"name,omitempty"` // its plain name, e.g. api.payments.kevaso
	// Ports: per service port, where it's reachable on each network.
	Ports []ServicePortStatus `json:"ports,omitempty"`
	// LoadBalancerIP is the address of its loadBalancer ports (its IP's), when it has one.
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`
	EgressIP       string `json:"egressIP,omitempty"` // where its outgoing traffic comes from: the address out
	// EgressNote says why the address out isn't the address in, when it isn't (design §7.2b).
	EgressNote string `json:"egressNote,omitempty"`
	// IP is the IP object its load-balancer address is, when it has one (design §7.2c-1).
	IP string `json:"ip,omitempty"`
	// HostAddresses are the host's own extra addresses this silo holds (IPs of type Host, in or
	// out): the host puts them on its uplink.
	HostAddresses []string `json:"hostAddresses,omitempty"`
	// NodePorts: for load-balancer classes that send to the host on ports of their own, which
	// host port each service port arrives on (the host forwards it to the silo), and from where.
	NodePorts    []NodePort `json:"nodePorts,omitempty"`
	SourceRanges []string   `json:"sourceRanges,omitempty"`
	// Announce: the load-balancer address is routed to the silo's host, which puts it on its
	// loopback (a shared IP announced over BGP).
	Announce bool `json:"announce,omitempty"`
}

// ServicePortStatus is where one service port is reachable: ADDRESS:PORT on each network it's
// open on ("" where it isn't).
type ServicePortStatus struct {
	Port         string `json:"port"`                   // the declared port's name
	Mesh         string `json:"mesh,omitempty"`         // its silo IP, to the silos allowFrom names
	Internal     string `json:"internal,omitempty"`     // its host's internal IP (hostPort: internal)
	External     string `json:"external,omitempty"`     // its host's external IP (hostPort: external)
	LoadBalancer string `json:"loadBalancer,omitempty"` // its load-balancer address (a LoadBalancer service)
}

// NodePort is the host port a service port arrives on from a load balancer.
type NodePort struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	NodePort int    `json:"nodePort"`
}

// Equal reports whether two service statuses are the same.
func (a SiloServiceStatus) Equal(b SiloServiceStatus) bool {
	if a.Name != b.Name || a.LoadBalancerIP != b.LoadBalancerIP || !slices.Equal(a.Ports, b.Ports) || a.EgressIP != b.EgressIP || a.EgressNote != b.EgressNote || a.IP != b.IP || a.Announce != b.Announce ||
		len(a.NodePorts) != len(b.NodePorts) || len(a.SourceRanges) != len(b.SourceRanges) || !slices.Equal(a.HostAddresses, b.HostAddresses) {
		return false
	}
	for i := range a.NodePorts {
		if a.NodePorts[i] != b.NodePorts[i] {
			return false
		}
	}
	for i := range a.SourceRanges {
		if a.SourceRanges[i] != b.SourceRanges[i] {
			return false
		}
	}
	return true
}

// KevasoRanges are Kevaso's own networks: the mesh (10.62/16, 10.63/16), the silos (10.64/16) and
// the Services' virtual IPs (10.65/16). A host port never answers on them, or a silo on another
// host could reach it over the mesh without its allowFrom. A grant never opens them through the
// egress gate either (ClosedRange).
var KevasoRanges = []string{"10.62.0.0/16", "10.63.0.0/16", "10.64.0.0/16", "10.65.0.0/16"}

// closedRange is one range a grant never opens (K-124).
type closedRange struct {
	p   netip.Prefix
	why string
}

// closedRanges are the cluster's own ranges (KevasoRanges: the mesh, the silos, the services),
// loopback, link-local, and what Special calls this-network, multicast or reserved. Those last
// ones are not reachable as ordinary egress: 0.0.0.0 is this host, and multicast and reserved
// addresses are not a peer on the internet. The cluster ranges are the same prefixes the mesh
// and the firewall use.
func closedRanges() []closedRange {
	why := map[string]string{
		"10.62.0.0/16": "the mesh range",
		"10.63.0.0/16": "the mesh range",
		"10.64.0.0/16": "the silo range",
		ServiceCIDR:    "the service range",
	}
	out := make([]closedRange, 0, len(KevasoRanges)+8)
	for _, s := range KevasoRanges {
		p := netip.MustParsePrefix(s)
		w := why[p.String()]
		if w == "" {
			w = p.String()
		}
		out = append(out, closedRange{p, w})
	}
	out = append(out,
		closedRange{netip.MustParsePrefix("127.0.0.0/8"), "loopback"},
		closedRange{netip.MustParsePrefix("::1/128"), "loopback"},
		closedRange{netip.MustParsePrefix("169.254.0.0/16"), "link-local"},
		closedRange{netip.MustParsePrefix("fe80::/10"), "link-local"},
	)
	out = append(out, neverRouted()...) // this network, multicast and reserved are never opened
	return out
}

// neverRouted are the ranges Special calls this-network, multicast or reserved. A grant never
// opens them: they are not a host the internet can route a silo to.
func neverRouted() []closedRange {
	return []closedRange{
		{netip.MustParsePrefix("0.0.0.0/8"), "this network"},
		{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
		{netip.MustParsePrefix("240.0.0.0/4"), "reserved"},
		{netip.MustParsePrefix("ff00::/8"), "multicast"},
	}
}

// ClosedPrefixes are the ranges a grant never opens, in the order closedRanges lists them.
func ClosedPrefixes() []netip.Prefix {
	src := closedRanges()
	out := make([]netip.Prefix, len(src))
	for i, s := range src {
		out[i] = s.p
	}
	return out
}

// ClosedRange reports the range a grant never opens when p lies entirely inside one: an address
// or CIDR of the silo, service or mesh range, of loopback or link-local, or of this-network,
// multicast or reserved. A wider range (10.0.0.0/8, 0.0.0.0/0) is not inside them. why is ""
// when p is not inside one.
func ClosedRange(p netip.Prefix) (netip.Prefix, string) {
	if !p.IsValid() {
		return netip.Prefix{}, ""
	}
	p = p.Masked()
	a := p.Addr().Unmap().WithZone("")
	bits := p.Bits()
	if a != p.Addr().WithZone("") { // an IPv4-mapped address: judge the IPv4 address
		bits = a.BitLen()
	}
	best, why := netip.Prefix{}, ""
	for _, s := range closedRanges() {
		if s.p.Contains(a) && bits >= s.p.Bits() && (!best.IsValid() || s.p.Bits() > best.Bits()) {
			best, why = s.p, s.why
		}
	}
	return best, why
}

// NodePort range: like Kubernetes'.
const (
	NodePortMin = 30000
	NodePortMax = 32767
)

// VolumeLocal is the built-in storage class (the host's own disk).
const VolumeLocal = "local"

// PluginVolumes are the silo's volumes on a plugin's storage class, and its root disk's volume
// when spec.disk.class is one (DiskVolume).
func PluginVolumes(s *Silo) []Volume {
	var out []Volume
	for _, v := range s.Spec.Volumes {
		if v.Class != "" && v.Class != VolumeLocal {
			out = append(out, v)
		}
	}
	if d, ok := DiskVolume(s); ok {
		out = append(out, d)
	}
	return out
}

// RootDiskVolume names the volume that keeps a VM silo's own disk (an image file) when its
// spec.disk.class is a plugin's mount class. No volume a person names can be called that.
const RootDiskVolume = "disk.root"

// DiskVolume is the volume holding a cloud-hypervisor silo's root disk on a plugin's class
// (spec.disk.class), sized like the disk; ok is false for a local disk.
func DiskVolume(s *Silo) (Volume, bool) {
	c := s.Spec.Disk.Class
	if s.Spec.Runtime != "cloud-hypervisor" || c == "" || c == VolumeLocal {
		return Volume{}, false
	}
	return Volume{Name: RootDiskVolume, Class: c, Size: s.Spec.Disk.Size}, true
}

// ParseSource parses one address range a user wrote for the firewall (a port's sources): an IPv4
// address or CIDR, returned as the masked prefix (10.0.0.5/24 is 10.0.0.0/24, 1.2.3.4 is
// 1.2.3.4/32). What the rules can't express is refused with a message: IPv6 (also the IPv4-mapped
// form and a zone) until the rules support it, and anything that isn't an address or a CIDR.
func ParseSource(c string) (netip.Prefix, error) {
	var p netip.Prefix
	if pp, err := netip.ParsePrefix(c); err == nil {
		p = pp
	} else if a, err := netip.ParseAddr(c); err == nil {
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		return p, fmt.Errorf("%q isn't an address or CIDR", c)
	}
	if !p.Addr().Is4() {
		return p, fmt.Errorf("%q: IPv6 comes later; IPv4 for now", c)
	}
	return p.Masked(), nil
}

// NormalizeSources writes ranges in their one form: masked, a single address without /32, sorted,
// and without any range another one already holds (so a firewall set never has an overlap or a
// duplicate, which nft refuses). An entry ParseSource refuses is kept as it is (admission says so).
func NormalizeSources(in []string) []string {
	var ok []netip.Prefix
	var bad []string
	for _, c := range in {
		if p, err := ParseSource(c); err == nil {
			ok = append(ok, p)
		} else {
			bad = append(bad, c)
		}
	}
	slices.SortFunc(ok, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits() // the wider first
	})
	var out []string
	var last netip.Prefix
	for i, p := range ok {
		if i > 0 && last.Contains(p.Addr()) && last.Bits() <= p.Bits() {
			continue
		}
		last = p
		if p.Bits() == 32 {
			out = append(out, p.Addr().String())
		} else {
			out = append(out, p.String())
		}
	}
	return append(out, bad...)
}
