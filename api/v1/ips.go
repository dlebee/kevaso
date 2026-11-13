package v1

import (
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/api/meta"
)

// IP is an outside address kept as its own object (design §7.2c-1): peers, allowlists and DNS
// records point at an address, so it outlives the services using it today. There is no load
// balancer object: a balancer is what a plugin runs behind an address. Load-balancer services of a
// class in a namespace share one IP (DefaultIPName) and its balancer, each on its own ports, unless
// they name one (loadBalancer.ip) or ask for their own (dedicated). An address only one host can
// have at a time (ip-pool, an announced shared IP) is never shared: one silo holds it.
type IP struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IPSpec   `json:"spec"`
	Status          IPStatus `json:"status,omitempty"`
}

// IPSpec is where the address comes from and whether it's kept.
type IPSpec struct {
	// Class provides it: a plugin's load-balancer class, or ip-pool for a host's own extra addresses.
	Class string `json:"class"`
	// Reclaim: Retain (the default) keeps the address until the IP is deleted; Delete deletes the IP
	// (and releases the address) once nothing holds it.
	Reclaim string `json:"reclaim,omitempty"`
	// Placement hints, for a class that needs them before anything holds the address: the host
	// whose addresses ip-pool picks from, the provider's region a plugin reserves it in. Without
	// them the address is reserved where its first holder lands.
	Host   string `json:"host,omitempty"`
	Region string `json:"region,omitempty"`
	// Address asks for this address: one of the host's (ip-pool), or one you already own at the
	// provider (a class that can reserve). Empty: any.
	Address string `json:"address,omitempty"`
}

// IPStatus is the address and who holds it.
type IPStatus struct {
	Address string `json:"address,omitempty"`
	Host    string `json:"host,omitempty"`   // ip-pool: the host it's routed to
	Region  string `json:"region,omitempty"` // a plugin's: the provider's region it's in
	// Handle is the plugin's for the reservation, given back when it's released.
	Handle string `json:"handle,omitempty"`
	// BoundTo are who hold it, each with its ports: one silo for an address only one host can have
	// at a time (ip-pool, an announced shared IP), any number of silos and Services on their own
	// ports for a balancer's. Empty: reserved, held by nobody.
	BoundTo []IPHolder `json:"boundTo,omitempty"`
	// Waiting are the services that name it and can't have it yet, and why.
	Waiting []IPWaiting `json:"waiting,omitempty"`
	// Follows says where the address can go with its holder (the class's scope): host, region or
	// global.
	Follows    string           `json:"follows,omitempty"`
	Conditions []meta.Condition `json:"conditions,omitempty"`
}

// IPHolder is a silo or Service holding an IP, on its ports (PORT/PROTO).
type IPHolder struct {
	Holder string   `json:"holder"` // silo/NAME | service/NAME
	UID    string   `json:"uid"`
	Ports  []string `json:"ports,omitempty"`
}

// IPWaiting is a service that names an IP it can't have now.
type IPWaiting struct {
	Holder string `json:"holder"`
	UID    string `json:"uid"`
	Reason string `json:"reason"`
}

// Holds reports whether the object with uid holds the IP.
func (st IPStatus) Holds(uid string) bool {
	for _, h := range st.BoundTo {
		if uid != "" && h.UID == uid {
			return true
		}
	}
	return false
}

// WaitingReason is why the object with uid can't have the IP yet ("" if it isn't waiting).
func (st IPStatus) WaitingReason(uid string) string {
	for _, w := range st.Waiting {
		if w.UID == uid {
			return w.Reason
		}
	}
	return ""
}

// Holders lists who hold it, with their ports, for people.
func (st IPStatus) Holders() string {
	var out []string
	for _, h := range st.BoundTo {
		s := h.Holder
		if len(h.Ports) > 0 {
			s += " (" + strings.Join(h.Ports, ",") + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

// Reclaim policies.
const (
	ReclaimRetain = "Retain"
	ReclaimDelete = "Delete"
)

// FinalizerIP holds an IP until its address is released.
const FinalizerIP = "kevaso.com/ip"

// LabelDefaultIP marks a namespace's default IP of a class (its value: the class).
const LabelDefaultIP = "kevaso.com/default-ip"

// Kept reports whether the IP stays when nothing holds it.
func (ip *IP) Kept() bool { return ip.Spec.Reclaim != ReclaimDelete }

// Holders of an IP.
const (
	HolderSiloPrefix    = "silo/"
	HolderServicePrefix = "service/"
)

// IPWay is how a load-balancer service comes by its IP.
type IPWay int

// The ways.
const (
	IPNone    IPWay = iota // no IP: no port on a load balancer
	IPNamed                // it names one (loadBalancer.ip)
	IPMade                 // one of its own, made for it and named after it (dedicated, or an exclusive class)
	IPDefault              // the namespace's shared one for its class (DefaultIPName)
)

// DefaultIPName is the name of a namespace's shared IP of a class: every load-balancer service of
// that class there that names no IP and isn't dedicated is on it, each on its own ports.
func DefaultIPName(class string) string { return "default-" + class }

func ipOf(class, named, self string, dedicated, exclusive bool) (string, IPWay) {
	switch {
	case class == "":
		return "", IPNone
	case named != "":
		return named, IPNamed
	case dedicated || exclusive:
		return self, IPMade
	}
	return DefaultIPName(class), IPDefault
}

// SiloServiceIP is the IP a silo's own service has its address from, and how. exclusive: its
// class's address is one host's at a time (ip-pool, an announced shared IP), so it's never shared.
func SiloServiceIP(s *Silo, exclusive bool) (string, IPWay) {
	sv := s.Spec.Service
	if !s.Spec.LoadBalanced() || sv.LoadBalancer == nil {
		return "", IPNone
	}
	// A SiloSet's instances have the same ports, so they'd clash on one address: each has its own.
	dedicated := sv.LoadBalancer.Dedicated || slices.ContainsFunc(s.OwnerReferences, func(r meta.OwnerReference) bool { return r.Kind == "SiloSet" })
	return ipOf(sv.LoadBalancer.Class, sv.LoadBalancer.IP, s.Name, dedicated, exclusive || sv.LoadBalancer.Class == LBIPPool)
}

// ServiceIP is the IP a standalone Service of type LoadBalancer has its address from, and how.
func ServiceIP(svc *Service, exclusive bool) (string, IPWay) {
	if svc.Spec.Type != ServiceLoadBalancer {
		return "", IPNone
	}
	return ipOf(svc.Spec.LoadBalancerClass, svc.Spec.LoadBalancerIP, svc.Name, svc.Spec.LoadBalancerDedicated, exclusive)
}

// SiloEgressIP is the IP a silo with egress.source pool sends from ("" otherwise): egress.ip, or
// its service's when that is ip-pool.
func SiloEgressIP(s *Silo) string {
	if s.Spec.Network.Egress.Source != EgressPool {
		return ""
	}
	if n := s.Spec.Network.Egress.IP; n != "" {
		return n
	}
	if sv := s.Spec.Service; sv != nil && sv.LoadBalancer != nil && sv.LoadBalancer.Class == LBIPPool {
		n, _ := SiloServiceIP(s, true)
		return n
	}
	return ""
}

// SiloIPs are the names of every IP a silo holds (its service's first); exclusive says which
// classes' addresses are one host's at a time.
func SiloIPs(s *Silo, exclusive func(class string) bool) []string {
	var out []string
	if sv := s.Spec.Service; sv != nil && sv.LoadBalancer != nil {
		if n, _ := SiloServiceIP(s, exclusive(sv.LoadBalancer.Class)); n != "" {
			out = append(out, n)
		}
	}
	if n := SiloEgressIP(s); n != "" && !slices.Contains(out, n) {
		out = append(out, n)
	}
	return out
}

// SiloPorts are the ports a silo's load balancer takes on its address (PORT/PROTO: their as),
// leased ones included: a closed port still has its number on the address.
func SiloPorts(s *Silo) []string {
	var out []string
	for _, p := range s.Spec.Open() {
		if p.LoadBalancer {
			out = append(out, portKey(p.HostNumber(), p.Protocol))
		}
	}
	return out
}

// ServicePorts are the ports a Service takes on its address.
func ServicePorts(svc *Service) []string {
	var out []string
	for _, p := range svc.Spec.Ports {
		out = append(out, portKey(p.Port, p.Protocol))
	}
	return out
}

func portKey(port int, proto string) string {
	if strings.EqualFold(proto, "UDP") {
		return fmt.Sprintf("%d/UDP", port)
	}
	return fmt.Sprintf("%d/TCP", port)
}

// OutsideIPs are the addresses its ports are reachable on outside the cluster (its host's
// internal and external IPs, its load-balancer address), each once, in port order.
func (st SiloServiceStatus) OutsideIPs() []string {
	var out []string
	for _, p := range st.Ports {
		for _, a := range []string{p.Internal, p.External, p.LoadBalancer} {
			if h, _, ok := strings.Cut(a, ":"); ok && !slices.Contains(out, h) {
				out = append(out, h)
			}
		}
	}
	return out
}

// Front is the address the outside reaches the service on, for one name to point at (an
// Ingress host's DNS record): its load-balancer address, else its host's external IP, else its
// internal IP ("" if no port opens outside).
func (st SiloServiceStatus) Front() string {
	if st.LoadBalancerIP != "" {
		return st.LoadBalancerIP
	}
	for _, pick := range []func(ServicePortStatus) string{
		func(p ServicePortStatus) string { return p.External },
		func(p ServicePortStatus) string { return p.Internal },
	} {
		for _, p := range st.Ports {
			if h, _, ok := strings.Cut(pick(p), ":"); ok {
				return h
			}
		}
	}
	return ""
}

// AddressesLine says in one line whether a silo's address out is its address in, and why not.
func (st SiloServiceStatus) AddressesLine() string {
	ins := st.OutsideIPs()
	in, out := strings.Join(ins, ", "), st.EgressIP
	why := ""
	if st.EgressNote != "" {
		why = ": " + st.EgressNote
	}
	switch {
	case in == "" && out == "":
		return "no outside address in or out" + why
	case in == "":
		return "out " + out + ", nothing in" + why
	case in == out || (out != "" && slices.Contains(ins, out)):
		if len(ins) > 1 {
			return "in " + in + ", out " + out + " (the same as one in)"
		}
		return "same address in and out: " + in
	case out == "":
		return "in " + in + ", out through the host's NAT" + why
	}
	return "in " + in + ", out " + out + why
}
