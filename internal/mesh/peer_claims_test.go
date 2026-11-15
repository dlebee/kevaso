package mesh

import (
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Found while re-checking the mesh for IPv6 (new; not an audit id yet). A worker may PUT its own
// Host status whole (internal/apiserver/auth.go, worker case: `t.kind.Kind == "Host" && t.name
// == id.Name`), and Plan takes each peer's meshIP and siloSubnet strings as they are into its
// WireGuard AllowedIPs and routes. A compromised worker that writes another host's silo subnet (or
// 0.0.0.0/0) as its own makes every other host send that host's silo traffic to it over the mesh.
// Fix, network lane: Plan derives a peer's addresses from its index (Addresses) and leaves out a
// peer whose index is out of range, is this host's own, or is shared with another peer. Fix,
// surface lane: a worker's Host status write may not change status.network other than its keys.
func TestAPeerCannotClaimAnotherHostsSubnet(t *testing.T) {
	t.Skip("new finding (mesh peer claims); see the comment: reported, not fixed in this pass")
	victim := host("victim", 3, "203.0.113.30", false)
	thief := host("thief", 4, "203.0.113.40", false)
	thief.Status.Network.SiloSubnet = victim.Status.Network.SiloSubnet // claims victim's silos
	d, err := Plan("me", []*v1.Host{host("me", 2, "203.0.113.20", false), victim, thief})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Outer.Peers {
		if p.Host == "thief" {
			for _, a := range p.AllowedIPs {
				if a == victim.Status.Network.SiloSubnet {
					t.Fatalf("thief's peer has the victim's subnet in AllowedIPs: %v", p.AllowedIPs)
				}
			}
		}
	}
}
