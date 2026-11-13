// Package mesh is the built-in mesh driver (design §7, research E023, E024): native WireGuard,
// with peers worked out by every host from the Host objects. Pure planning here; applying it with
// netlink and wgctrl is in apply_linux.go.
//
// Addresses: host n is 10.63.0.n on kevaso0 and routes its silos' 10.64.n.0/24. Public hosts
// connect directly. A host behind NAT dials the public hosts (keepalive holds its NAT mapping
// open). Two hosts behind NAT reach each other through a relay (a public host, control-plane hosts
// first), which forwards their outer packets; inside runs a second, end-to-end tunnel (kevaso1,
// 10.62.0.n), so the relay sees only encrypted UDP (E024).
package mesh

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"

	v1 "kevaso.com/core/api/v1"
)

// Interface names and ports.
const (
	Outer          = "kevaso0"
	Inner          = "kevaso1"
	DefaultPort    = 51820
	InnerPort      = 51821
	OuterMTU       = 1420
	InnerMTU       = 1340 // inside kevaso0: 80 bytes less (E024)
	Keepalive      = 25   // seconds: holds a NAT mapping open
	MaxHosts       = 255
	meshPrefix     = "10.63.0.0/16"
	innerPrefix    = "10.62.0.0/16"
	siloPrefixBase = "10.64.0.0/16"
)

// Addresses returns host index n's mesh IP, silo subnet and inner IP.
func Addresses(n int) (mesh, subnet, inner string) {
	return fmt.Sprintf("10.63.0.%d", n), fmt.Sprintf("10.64.%d.0/24", n), fmt.Sprintf("10.62.0.%d", n)
}

// Peer is one WireGuard peer.
type Peer struct {
	Host       string
	PublicKey  string
	Endpoint   string // host:port; empty: learned from the peer's own packets
	AllowedIPs []string
	Keepalive  int // seconds; 0: none
}

// Iface is one WireGuard interface's wanted state.
type Iface struct {
	Name       string
	Address    string // with prefix, e.g. 10.63.0.3/16
	ListenPort int
	MTU        int
	Peers      []Peer
	Routes     []string // prefixes outside Address's, routed into this interface
}

// Desired is a host's whole mesh.
type Desired struct {
	Outer   Iface
	Inner   *Iface // only behind NAT, with other NAT'd hosts
	Forward bool   // this host relays: IP forwarding on
	Relay   string // the relay this host uses or is ("" if none)
}

func port(h *v1.Host) int {
	if h.Spec.Network.ListenPort > 0 {
		return h.Spec.Network.ListenPort
	}
	return DefaultPort
}

func ready(h *v1.Host) bool {
	return h.Status.Network.Index > 0 && h.Status.Network.PublicKey != ""
}

// Plan works out self's mesh from every Host. Pure.
func Plan(self string, hosts []*v1.Host) (Desired, error) {
	var me *v1.Host
	var others []*v1.Host
	for _, h := range hosts {
		switch {
		case h.Name == self:
			me = h
		case ready(h):
			others = append(others, h)
		}
	}
	if me == nil || me.Status.Network.Index == 0 {
		return Desired{}, fmt.Errorf("host %s has no mesh index yet", self)
	}
	sort.Slice(others, func(i, j int) bool { return others[i].Status.Network.Index < others[j].Status.Network.Index })
	nat := func(h *v1.Host) bool { return h.Spec.Network.BehindNAT }

	// The relay: a public host, control-plane hosts first (they're the ones always up), then the
	// lowest index: the same answer on every host.
	relay, best := "", 0
	for _, h := range append([]*v1.Host{me}, others...) {
		if nat(h) {
			continue
		}
		rank := h.Status.Network.Index
		if h.Spec.Components.ControlPlane == nil {
			rank += 1 << 20
		}
		if relay == "" || rank < best {
			relay, best = h.Name, rank
		}
	}
	var natPeers []*v1.Host
	for _, h := range others {
		if nat(h) {
			natPeers = append(natPeers, h)
		}
	}

	n := me.Status.Network
	d := Desired{Relay: relay, Outer: Iface{Name: Outer, Address: n.MeshIP + "/16", ListenPort: port(me), MTU: OuterMTU}}
	for _, p := range others {
		pn := p.Status.Network
		peer := Peer{Host: p.Name, PublicKey: pn.PublicKey, AllowedIPs: []string{pn.MeshIP + "/32", pn.SiloSubnet}}
		switch {
		case !nat(me) && !nat(p): // both public: direct
			peer.Endpoint = fmt.Sprintf("%s:%d", p.Reach(), port(p))
		case !nat(me) && nat(p): // it dials us; WireGuard learns where it is
		case nat(me) && !nat(p): // we dial it, and keep our NAT mapping open
			peer.Endpoint, peer.Keepalive = fmt.Sprintf("%s:%d", p.Reach(), port(p)), Keepalive
			if p.Name == relay { // the other NAT'd hosts' outer addresses are reached through it
				for _, q := range natPeers {
					peer.AllowedIPs = append(peer.AllowedIPs, q.Status.Network.MeshIP+"/32")
				}
			}
		default: // both behind NAT: only through the relay, on the inner tunnel below
			continue
		}
		d.Outer.Peers = append(d.Outer.Peers, peer)
		d.Outer.Routes = append(d.Outer.Routes, pn.SiloSubnet)
	}
	if !nat(me) && me.Name == relay && len(natPeers) > 1 {
		d.Forward = true
	}
	if nat(me) && relay != "" && n.InnerPublicKey != "" {
		inner := Iface{Name: Inner, Address: n.InnerIP + "/16", ListenPort: InnerPort, MTU: InnerMTU}
		for _, q := range natPeers {
			qn := q.Status.Network
			if qn.InnerPublicKey == "" {
				continue
			}
			inner.Peers = append(inner.Peers, Peer{Host: q.Name, PublicKey: qn.InnerPublicKey,
				Endpoint: fmt.Sprintf("%s:%d", qn.MeshIP, InnerPort), Keepalive: Keepalive,
				AllowedIPs: []string{qn.InnerIP + "/32", qn.SiloSubnet}})
			inner.Routes = append(inner.Routes, qn.SiloSubnet)
		}
		if len(inner.Peers) > 0 {
			d.Inner = &inner
		}
	}
	return d, nil
}

// AssignIndexes gives every host without a mesh index the smallest free one (1…MaxHosts). It
// returns only the hosts it assigned, by name. Pure.
func AssignIndexes(hosts []*v1.Host) (map[string]int, error) {
	used := map[int]bool{}
	var need []string
	for _, h := range hosts {
		if i := h.Status.Network.Index; i > 0 {
			used[i] = true
		} else {
			need = append(need, h.Name)
		}
	}
	slices.Sort(need)
	out := map[string]int{}
	next := 1
	for _, name := range need {
		for used[next] {
			next++
		}
		if next > MaxHosts {
			return out, fmt.Errorf("no mesh index left for %s (at most %d hosts for now)", name, MaxHosts)
		}
		used[next] = true
		out[name] = next
	}
	return out, nil
}

// Prefixes the mesh owns, for firewalls (silos may not reach them).
var (
	MeshPrefix  = netip.MustParsePrefix(meshPrefix)
	InnerPrefix = netip.MustParsePrefix(innerPrefix)
	SiloPrefix  = netip.MustParsePrefix(siloPrefixBase)
)
