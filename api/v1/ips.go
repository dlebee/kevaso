package v1

import (
	"slices"

	"kevaso.com/core/api/meta"
)

// IP is an outside address kept as its own object (design §7.2c-1): peers, allowlists and DNS
// records point at an address, so it outlives the service using it today. A service refers to one
// (loadBalancer.ip); a load-balancer service that names none gets one made for it, which goes with
// it unless kept. An IP serves one silo or one Service at a time.
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
	// BoundTo is who holds it: silo/NAME or service/NAME; empty: reserved, held by nobody.
	BoundTo  string `json:"boundTo,omitempty"`
	BoundUID string `json:"boundUID,omitempty"`
	// Follows says where the address can go with its holder (the class's scope): host, region or
	// global.
	Follows    string           `json:"follows,omitempty"`
	Conditions []meta.Condition `json:"conditions,omitempty"`
}

// Reclaim policies.
const (
	ReclaimRetain = "Retain"
	ReclaimDelete = "Delete"
)

// FinalizerIP holds an IP until its address is released.
const FinalizerIP = "kevaso.com/ip"

// Kept reports whether the IP stays when nothing holds it.
func (ip *IP) Kept() bool { return ip.Spec.Reclaim != ReclaimDelete }

// Holders of an IP.
const (
	HolderSiloPrefix    = "silo/"
	HolderServicePrefix = "service/"
)

// SiloServiceIP is the IP a silo's own service has its address from, and whether it's one made
// for it (none named). "" when its exposure has none (private, hostPort, worker-ip).
func SiloServiceIP(s *Silo) (name string, made bool) {
	sv := s.Spec.Service
	if sv == nil || sv.Expose != ExposeLoadBalancer || sv.LoadBalancer == nil || sv.LoadBalancer.Class == "" || sv.LoadBalancer.Class == LBWorkerIP {
		return "", false
	}
	if sv.LoadBalancer.IP != "" {
		return sv.LoadBalancer.IP, false
	}
	return s.Name, true
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
		n, _ := SiloServiceIP(s)
		return n
	}
	return ""
}

// SiloIPs are the names of every IP a silo holds (its service's first).
func SiloIPs(s *Silo) []string {
	var out []string
	if n, _ := SiloServiceIP(s); n != "" {
		out = append(out, n)
	}
	if n := SiloEgressIP(s); n != "" && !slices.Contains(out, n) {
		out = append(out, n)
	}
	return out
}

// ServiceIP is the IP a standalone Service of type LoadBalancer has its address from, and whether
// it's one made for it.
func ServiceIP(svc *Service) (name string, made bool) {
	if svc.Spec.Type != ServiceLoadBalancer || svc.Spec.LoadBalancerClass == "" {
		return "", false
	}
	if svc.Spec.LoadBalancerIP != "" {
		return svc.Spec.LoadBalancerIP, false
	}
	return svc.Name, true
}

// AddressesLine says in one line whether a silo's address out is its address in, and why not.
func (st SiloServiceStatus) AddressesLine() string {
	in, out := st.PublicIP, st.EgressIP
	why := ""
	if st.EgressNote != "" {
		why = ": " + st.EgressNote
	}
	switch {
	case in == "" && out == "":
		return "no outside address in or out" + why
	case in == "":
		return "out " + out + ", nothing in" + why
	case in == out:
		return "same address in and out: " + in
	case out == "":
		return "in " + in + ", out through the host's NAT" + why
	}
	return "in " + in + ", out " + out + why
}
