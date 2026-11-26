package v1

import (
	"fmt"
	"slices"
	"strings"

	"kevaso.com/core/api/meta"
)

// IP is one address a namespace keeps (networking v2), with an explicit type, never guessed from
// its fields:
//   - type Host: one of a host's named extra addresses (spec.hostAddress): pinned to that host;
//   - type Provider: an address reserved from a provider (spec.provider, spec.region): it follows
//     its silo within the provider's reach.
//
// One IP is exactly one address (a range is an IPSet) and has one holder at a time. Deleting the
// silo keeps the IP: the next silo naming it gets the same address.
type IP struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IPSpec   `json:"spec"`
	Status          IPStatus `json:"status,omitempty"`
}

// IP types.
const (
	IPTypeHost     = "Host"
	IPTypeProvider = "Provider"
)

// IPSpec is where the address comes from: Host requires hostAddress, Provider requires provider
// and region; the other fields are refused.
type IPSpec struct {
	Type        string `json:"type"`
	HostAddress string `json:"hostAddress,omitempty"` // type Host: a host's extra address, by name
	Provider    string `json:"provider,omitempty"`    // type Provider: the installed provider, e.g. linode
	Region      string `json:"region,omitempty"`      // type Provider: its region, e.g. us-ord
}

// IPStatus is the address, who holds it and where it is.
type IPStatus struct {
	Address string `json:"address,omitempty"`
	// Holder is the silo or Service holding it now (one at a time); nil: reserved, held by nobody.
	Holder *IPHolder `json:"holder,omitempty"`
	// Where is where the address can be, for people: "host NAME" (type Host) or "PROVIDER REGION".
	Where string `json:"where,omitempty"`
	// Host is the host the address is on now: its host's (type Host), or the worker announcing it
	// (type Provider).
	Host   string `json:"host,omitempty"`
	Region string `json:"region,omitempty"` // type Provider: the provider's region it's in
	// Announce (type Provider): the provider routes the address to Host, which puts it on its
	// loopback, where the provider's node side announces it (BGP); otherwise Host puts it on its
	// uplink.
	Announce bool `json:"announce,omitempty"`
	// Handle is the provider's for the reservation, given back when it's released.
	Handle string `json:"handle,omitempty"`
	// Waiting are the others that name it and can't have it now, and why.
	Waiting    []IPWaiting      `json:"waiting,omitempty"`
	Conditions []meta.Condition `json:"conditions,omitempty"`
}

// IPHolder is a silo or Service holding an IP, on its ports (PORT/PROTO).
type IPHolder struct {
	Holder string   `json:"holder"` // silo/NAME | service/NAME
	UID    string   `json:"uid"`
	Ports  []string `json:"ports,omitempty"`
}

// IPWaiting is one that names an IP it can't have now.
type IPWaiting struct {
	Holder string `json:"holder"`
	UID    string `json:"uid"`
	Reason string `json:"reason"`
}

// Holds reports whether the object with uid holds the IP.
func (st IPStatus) Holds(uid string) bool {
	return uid != "" && st.Holder != nil && st.Holder.UID == uid
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

// Holders says who holds it, with its ports, for people ("" for nobody).
func (st IPStatus) Holders() string {
	if st.Holder == nil {
		return ""
	}
	s := st.Holder.Holder
	if len(st.Holder.Ports) > 0 {
		s += " (" + strings.Join(st.Holder.Ports, ",") + ")"
	}
	return s
}

// FinalizerIP holds an IP until its address is released.
const FinalizerIP = "kevaso.com/ip"

// Holders of an IP.
const (
	HolderSiloPrefix    = "silo/"
	HolderServicePrefix = "service/"
)

// ── IPSet ────────────────────────────────────────────────────────────────────

// IPSet is one reservation per SiloSet instance, matched by ordinal (like a StatefulSet's
// volumeClaimTemplates). A SiloSet names it (spec.ips) when its template uses own:
//   - type Static: an ordered list of members, each an IP (ip: NAME) or a host's extra address
//     (hostAddress: NAME). It never grows on its own; members are only added at the end, never
//     renumbered or removed.
//   - type Dynamic: Kevaso reserves provider IPs as instances need them, up to max, kept per
//     ordinal (SET-0, SET-1, …). A Dynamic set has no host addresses.
//
// Its members are ordinary IP objects (labelled LabelIPSet and LabelIPSetOrdinal), so kvo get ips
// lists everything. Namespaced.
type IPSet struct {
	meta.TypeMeta   `json:",inline"`
	meta.ObjectMeta `json:"metadata"`
	Spec            IPSetSpec   `json:"spec"`
	Status          IPSetStatus `json:"status,omitempty"`
}

// IPSet types.
const (
	IPSetStatic  = "Static"
	IPSetDynamic = "Dynamic"
)

// IPSetSpec: Static requires members; Dynamic requires provider, region and max; the other fields
// are refused.
type IPSetSpec struct {
	Type     string        `json:"type"`
	Members  []IPSetMember `json:"members,omitempty"`
	Provider string        `json:"provider,omitempty"`
	Region   string        `json:"region,omitempty"`
	Max      int           `json:"max,omitempty"`
}

// IPSetMember is one ordinal of a Static set: exactly one of ip and hostAddress.
type IPSetMember struct {
	IP          string `json:"ip,omitempty"`          // an IP in this namespace
	HostAddress string `json:"hostAddress,omitempty"` // a host's extra address, by name
}

// String is the member as a person writes it.
func (m IPSetMember) String() string {
	if m.IP != "" {
		return "ip: " + m.IP
	}
	return "hostAddress: " + m.HostAddress
}

// IPSetStatus is the set's members as its controller sees them.
type IPSetStatus struct {
	Members    []IPSetMemberStatus `json:"members,omitempty"`
	Conditions []meta.Condition    `json:"conditions,omitempty"`
}

// IPSetMemberStatus is one ordinal: its IP object, address and user.
type IPSetMemberStatus struct {
	Ordinal int    `json:"ordinal"`
	IP      string `json:"ip"`
	Address string `json:"address,omitempty"`
	UsedBy  string `json:"usedBy,omitempty"` // the instance on it
}

// Labels on an IPSet's member IPs.
const (
	LabelIPSet        = "kevaso.com/ipset"
	LabelIPSetOrdinal = "kevaso.com/ipset-ordinal"
)

// DynamicMemberName is the IP a Dynamic set reserves for ordinal i: SET-i.
func DynamicMemberName(set string, i int) string { return InstanceName(set, i) }

// SiloIPs are the names of every IP a silo names (services first, then egress).
func SiloIPs(s *Silo) []string {
	var out []string
	for _, n := range s.Spec.NamedIPs() {
		out = append(out, n.Name)
	}
	return out
}

// SiloPortsOn are the ports a silo takes on the IP named ip (PORT/PROTO: their as), from the
// services that name it, leased ones included: a closed port still has its number on the address.
func SiloPortsOn(s *Silo, ip string) []string {
	var out []string
	for _, sv := range s.Spec.Services {
		on := (sv.HostPort != nil && sv.HostPort.IP == ip) || (sv.LoadBalancer != nil && sv.LoadBalancer.IP == ip)
		if !on {
			continue
		}
		for _, p := range sv.Ports {
			if d, ok := s.Spec.Declared(p.Port); ok {
				n := p.As
				if n == 0 {
					n = d.Port
				}
				if k := portKey(n, d.Proto()); !slices.Contains(out, k) {
					out = append(out, k)
				}
			}
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
