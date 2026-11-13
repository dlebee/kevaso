package names

import (
	"net/netip"
	"strings"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/routing"
)

// Asker is who asks a name, known by where the question arrived (design §7.0, ADR 0009 §5).
type Asker int

const (
	// FromSilo: a silo, on its host's bridge. It resolves services by their plain name (the mesh
	// answer), short names included, and nothing else.
	FromSilo Asker = iota
	// FromHost: a host in the cluster, on its mesh IP (or an operator through one): everything.
	FromHost
	// FromNetwork: a machine on a host's network, asking on the host's internal IP: internal and
	// external names, of services and hosts.
	FromNetwork
	// FromOutside: anyone else, asking on the host's external IP: external names only.
	FromOutside
)

func (a Asker) String() string {
	return [...]string{"a silo", "a host", "a machine on a host's network", "anyone else"}[a]
}

// View is what names answer from.
type View struct {
	Silos    []*v1.Silo
	Services []*v1.Service
	Hosts    []*v1.Host
	Suffix   string // the cluster's last label ("": kevaso)
}

// Question is one name, asked by From; Namespace is an asking silo's (its short names).
type Question struct {
	Name      string
	From      Asker
	Namespace string
}

// Answer is what a name answers.
type Answer struct {
	// InZone: the name is Kevaso's to answer. A silo's other names are forwarded upstream; nobody
	// else's are (a Kevaso host is no open resolver).
	InZone bool
	// Refused: this asker may not resolve such names (a silo asking a host's name, anyone else an
	// internal one). Nothing is said about whether it exists.
	Refused bool
	// Found: the name exists (false: NXDOMAIN). A name with no address from there, or held back
	// by routeWhen, is found with no IPs (NODATA).
	Found bool
	IPs   []netip.Addr
	// Network is the network the answer is on (mesh, internal, external), for a found name.
	Network string
}

// Resolve answers one question (design §7.0's grammar and table). Pure.
//
//	SERVICE.NAMESPACE.SUFFIX           the plain name: mesh for a silo or a host, internal for a
//	                                   machine on a host's network (external if it has no internal
//	                                   answer), external for anyone else
//	SERVICE.NAMESPACE.NETWORK.SUFFIX   that network's answer
//	HOST.NETWORK.SUFFIX                that host's address there
//	SERVICE, SERVICE.NAMESPACE         short names, from a silo only (outside the zone)
func Resolve(q Question, v View) Answer {
	suffix := v.Suffix
	if suffix == "" {
		suffix = v1.DefaultSuffix
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	zone := strings.ToLower(suffix)
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return short(q, name, v)
	}
	labels := strings.Split(strings.TrimSuffix(strings.TrimSuffix(name, zone), "."), ".")
	if name == zone {
		labels = nil
	}
	out := Answer{InZone: true}
	switch {
	case len(labels) == 2 && isNetwork(labels[1]): // HOST.NETWORK
		if !may(q.From, labels[1], true) {
			out.Refused = true
			return out
		}
		return hostAnswer(labels[0], labels[1], v)
	case len(labels) == 2: // SERVICE.NAMESPACE: the plain name
		return plain(q.From, labels[0], labels[1], v)
	case len(labels) == 3 && isNetwork(labels[2]): // SERVICE.NAMESPACE.NETWORK
		if !may(q.From, labels[2], false) {
			out.Refused = true
			return out
		}
		return serviceAnswer(labels[0], labels[1], labels[2], v)
	}
	return out // not a name of ours' shape: NXDOMAIN
}

// short is a silo's short name (api, api.billing), when it names a service; anything else isn't
// Kevaso's (forwarded).
func short(q Question, name string, v View) Answer {
	if q.From != FromSilo || name == "" {
		return Answer{}
	}
	labels := strings.Split(name, ".")
	ns := q.Namespace
	switch len(labels) {
	case 1:
	case 2:
		ns = labels[1]
	default:
		return Answer{}
	}
	if s, svc := Owner(ns, labels[0], v.Silos, v.Services); s == nil && svc == nil {
		return Answer{} // not one of ours: example.com stays example.com
	}
	a := serviceAnswer(labels[0], ns, v1.NetworkMesh, v)
	a.InZone = true
	return a
}

func isNetwork(l string) bool { return Reserved(l) }

// may says whether an asker may resolve a name on network (host: a host's name).
func may(from Asker, network string, host bool) bool {
	switch from {
	case FromHost:
		return true
	case FromNetwork:
		return network != v1.NetworkMesh
	case FromOutside:
		return network == v1.NetworkExternal
	}
	return false // a silo: plain service names only
}

// plain is the plain name's answer for the asker: the best network from where it asks.
func plain(from Asker, svc, ns string, v View) Answer {
	switch from {
	case FromSilo, FromHost:
		return serviceAnswer(svc, ns, v1.NetworkMesh, v)
	case FromNetwork:
		a := serviceAnswer(svc, ns, v1.NetworkInternal, v)
		if a.Found && len(a.IPs) == 0 {
			if b := serviceAnswer(svc, ns, v1.NetworkExternal, v); len(b.IPs) > 0 {
				return b
			}
		}
		return a
	}
	return serviceAnswer(svc, ns, v1.NetworkExternal, v)
}

func hostAnswer(name, network string, v View) Answer {
	out := Answer{InZone: true, Network: network}
	for _, h := range v.Hosts {
		if h.Name != name || h.DeletionTimestamp != nil {
			continue
		}
		out.Found = true
		addr := h.IPOn(network)
		if network == v1.NetworkMesh {
			addr = h.Status.Network.MeshIP
		}
		if a, err := netip.ParseAddr(addr); err == nil {
			out.IPs = append(out.IPs, a)
		}
	}
	return out
}

// serviceAnswer is a service's addresses on network: on the mesh, its silo's silo IP (a Service:
// its cluster IP); internal and external, the address of that kind of each host where a port of
// it has hostPort on that network (a Service: of its endpoints' hosts). A silo held back by its
// routeWhen, or not running, has no address.
func serviceAnswer(svc, ns, network string, v View) Answer {
	out := Answer{InZone: true, Network: network}
	s, sv := Owner(ns, svc, v.Silos, v.Services)
	switch {
	case sv != nil:
		out.Found = true
		if network == v1.NetworkMesh {
			if a, err := netip.ParseAddr(sv.Status.ClusterIP); err == nil {
				out.IPs = append(out.IPs, a)
			}
			return out
		}
		for _, ep := range sv.Status.Endpoints {
			for _, x := range v.Silos {
				if x.Namespace == ns && x.Name == ep.Silo {
					out.IPs = appendNew(out.IPs, siloOn(x, network, v)...)
				}
			}
		}
	case s != nil:
		out.Found = true
		out.IPs = siloOn(s, network, v)
	}
	return out
}

// siloOn is a silo's own service's address on network, if it has one there now.
func siloOn(s *v1.Silo, network string, v View) []netip.Addr {
	if s.Spec.Service == nil || !routing.Routed(s) || s.Status.SiloIP == "" {
		return nil
	}
	if network == v1.NetworkMesh {
		if a, err := netip.ParseAddr(s.Status.SiloIP); err == nil {
			return []netip.Addr{a}
		}
		return nil
	}
	opens := false
	for _, p := range s.Spec.Open() {
		opens = opens || p.On(network)
	}
	if !opens {
		return nil
	}
	for _, h := range v.Hosts {
		if h.Name == s.Status.Host {
			if a, err := netip.ParseAddr(h.IPOn(network)); err == nil {
				return []netip.Addr{a}
			}
		}
	}
	return nil
}

func appendNew(l []netip.Addr, more ...netip.Addr) []netip.Addr {
	for _, a := range more {
		found := false
		for _, b := range l {
			found = found || a == b
		}
		if !found {
			l = append(l, a)
		}
	}
	return l
}
