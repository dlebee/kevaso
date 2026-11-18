package v1

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Ports and services (design §7.0): a silo declares its ports (spec.ports); its service
// (spec.service) is what makes any of them reachable, port by port: by which silos (allowFrom), on
// which of its host's addresses (hostPort, as, sources), on a lease, behind a load balancer. A
// silo without a service has a silo IP for its own traffic, no name, and nothing reachable.

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

// Load-balancer classes built in.
const (
	LBIPPool = "ip-pool" // an address of its own: an IP from the host's extra addresses (spec.network.addresses)
)

// Egress sources: which address a silo's outgoing traffic leaves from.
const (
	EgressHost          = "host"          // the host's main address (default)
	EgressSameAsService = "sameAsService" // the address the silo is reached on
	EgressPool          = "pool"          // an address of its own: an IP of class ip-pool (egress.ip)
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

// SiloService is a silo's own service: its name, and which of its declared ports are reachable
// and how.
type SiloService struct {
	// Name is what others resolve (SERVICE.NAMESPACE[.NETWORK].kevaso); default: the silo's
	// name. Unique in the namespace, across silos' services and standalone Services.
	Name  string        `json:"name,omitempty"`
	Ports []ServicePort `json:"ports,omitempty"`
	// LoadBalancer is where the ports with loadBalancer: true get their address: the class, and
	// which IP (design §7.2c-1).
	LoadBalancer *LoadBalancerSpec `json:"loadBalancer,omitempty"`
	// RouteWhen: ready (traffic only while the readiness probe passes) or running (as soon as the
	// silo runs). Required with a readiness probe; without one it's running (design §0.6).
	RouteWhen string `json:"routeWhen,omitempty"`
}

// ServicePort opens one declared port: everything about reaching it is here.
type ServicePort struct {
	Port string `json:"port"` // a declared port's name (spec.ports)
	// AllowFrom are the silos that may connect to it on its silo IP: NAME (this namespace) or
	// NAMESPACE/NAME.
	AllowFrom []string `json:"allowFrom,omitempty"`
	// HostPort: which of its host's addresses it opens on, internal and/or external. Absent: not
	// on the host.
	HostPort []string `json:"hostPort,omitempty"`
	// As is the number on the host or the load balancer (default: the declared port's).
	As int `json:"as,omitempty"`
	// Sources are the network ranges (CIDRs) that may connect on the host or the load balancer;
	// absent: anyone who can reach that address.
	Sources []string `json:"sources,omitempty"`
	// Lease: the port opens on the host or the load balancer only on a lease, on its own terms
	// (design §7.2d).
	Lease *PortLease `json:"lease,omitempty"`
	// LoadBalancer: the port is reachable on the service's load-balancer address (its class and
	// IP: service.loadBalancer).
	LoadBalancer bool `json:"loadBalancer,omitempty"`
}

// Outside says whether the port opens anywhere but its silo IP: on the host, or a load balancer.
func (p ServicePort) Outside() bool { return len(p.HostPort) > 0 || p.LoadBalancer }

// On says whether the port opens on the host's address on network (internal | external).
func (p ServicePort) On(network string) bool { return slices.Contains(p.HostPort, network) }

// LoadBalancerSpec is where a service's loadBalancer ports get their address.
type LoadBalancerSpec struct {
	Class string `json:"class"`
	// IP names the IP object (design §7.2c-1) whose address this is. Empty: the namespace's shared
	// one for the class (made on first use, gone with its last service unless kept), or with
	// Dedicated one of its own.
	IP string `json:"ip,omitempty"`
	// Dedicated: an IP of its own, made for it and named after it, instead of the namespace's
	// shared one for the class. An address only one host can have at a time is always its own.
	Dedicated bool `json:"dedicated,omitempty"`
}

// OpenPort is a service port with the declared port it names.
type OpenPort struct {
	ServicePort
	Name     string // the declared port's name
	Number   int    // its number in the silo
	Protocol string // TCP | UDP
}

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

// Open are the service's ports, each with its declared port, in the service's order; a service
// port naming no declared port is left out (admission refuses it).
func (s SiloSpec) Open() []OpenPort {
	if s.Service == nil {
		return nil
	}
	var out []OpenPort
	for _, sp := range s.Service.Ports {
		d, ok := s.Declared(sp.Port)
		if !ok {
			continue
		}
		out = append(out, OpenPort{ServicePort: sp, Name: d.Name, Number: d.Port, Protocol: d.Proto()})
	}
	return out
}

// OpenPort is the service port opening the declared port name (ok false: the service doesn't).
func (s SiloSpec) OpenPort(name string) (OpenPort, bool) {
	for _, p := range s.Open() {
		if p.Name == name {
			return p, true
		}
	}
	return OpenPort{}, false
}

// LoadBalanced says whether any of the service's ports is on its load balancer.
func (s SiloSpec) LoadBalanced() bool {
	for _, p := range s.Open() {
		if p.LoadBalancer {
			return true
		}
	}
	return false
}

// OnHost says whether any of the service's ports opens on the host's own addresses.
func (s SiloSpec) OnHost() bool {
	for _, p := range s.Open() {
		if len(p.HostPort) > 0 {
			return true
		}
	}
	return false
}

// LBClass is the service's load-balancer class when it has a port on it ("" if none).
func (s SiloSpec) LBClass() string {
	if !s.LoadBalanced() || s.Service.LoadBalancer == nil {
		return ""
	}
	return s.Service.LoadBalancer.Class
}

// ServiceName is the silo's service name: service.name, or the silo's own name; "" for a silo
// without a service, which has no name.
func ServiceName(s *Silo) string {
	if s.Spec.Service == nil {
		return ""
	}
	if s.Spec.Service.Name != "" {
		return s.Spec.Service.Name
	}
	return s.Name
}

// AllowedFrom says whether the silo caller (namespace/name) may connect to port on s, by s's
// service's allowFrom.
func AllowedFrom(s *Silo, port, caller string) bool {
	p, ok := s.Spec.OpenPort(port)
	if !ok {
		return false
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
	return false
}

// SiloNetwork is a silo's outbound choices.
type SiloNetwork struct {
	Egress Egress `json:"egress,omitempty"`
}

// Egress picks the source address.
type Egress struct {
	Source string `json:"source,omitempty"` // host (default) | sameAsService | pool
	// IP is the IP (class ip-pool) to send from with source pool; empty: the service's, when its
	// load balancer is ip-pool.
	IP string `json:"ip,omitempty"`
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
	// HostAddresses are the host's own extra addresses this silo holds (IPs of class ip-pool, in or
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
	LoadBalancer string `json:"loadBalancer,omitempty"` // its load-balancer address (loadBalancer: true)
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

// IsBuiltinLB says whether a load-balancer class is built in (the others come from plugins).
func IsBuiltinLB(class string) bool { return class == LBIPPool }

// PluginLB is the silo's plugin load-balancer class ("" if it has none).
func PluginLB(s *Silo) string {
	c := s.Spec.LBClass()
	if c == "" || IsBuiltinLB(c) {
		return ""
	}
	return c
}

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
