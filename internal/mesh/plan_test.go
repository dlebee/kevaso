package mesh

import (
	"slices"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func host(name string, index int, addr string, nat bool) *v1.Host {
	h := &v1.Host{}
	h.Name, h.Spec.ExternalIP, h.Spec.Network.BehindNAT = name, addr, nat
	m, sub, in := Addresses(index)
	h.Status.Network = v1.NetworkStatus{Index: index, MeshIP: m, SiloSubnet: sub, PublicKey: "pk-" + name}
	if nat {
		h.Status.Network.InnerIP, h.Status.Network.InnerPublicKey = in, "ipk-"+name
	}
	return h
}

func cpHost(name string, index int, addr string) *v1.Host {
	h := host(name, index, addr, false)
	h.Spec.Components.ControlPlane = &v1.ControlPlaneSpec{}
	return h
}

func peer(i Iface, host string) *Peer {
	for k := range i.Peers {
		if i.Peers[k].Host == host {
			return &i.Peers[k]
		}
	}
	return nil
}

// cp-1 and worker-1 are public; home and office are behind NAT.
func cluster() []*v1.Host {
	return []*v1.Host{
		cpHost("cp-1", 2, "203.0.113.10"),
		host("worker-1", 1, "198.51.100.30", false), // a lower index, but the control plane relays
		host("home", 3, "192.168.1.20", true),
		host("office", 4, "192.168.2.20", true),
	}
}

func TestPublicHostsConnectDirectly(t *testing.T) {
	d, err := Plan("worker-1", cluster())
	if err != nil {
		t.Fatal(err)
	}
	if d.Outer.Address != "10.63.0.1/16" || d.Outer.ListenPort != 51820 || d.Relay != "cp-1" || d.Forward || d.Inner != nil {
		t.Fatalf("%+v", d)
	}
	cp := peer(d.Outer, "cp-1")
	if cp.Endpoint != "203.0.113.10:51820" || cp.Keepalive != 0 || !slices.Equal(cp.AllowedIPs, []string{"10.63.0.2/32", "10.64.2.0/24"}) {
		t.Fatalf("cp-1 peer %+v", cp)
	}
	// NAT'd hosts: no endpoint (they dial us), but they're peers.
	if h := peer(d.Outer, "home"); h == nil || h.Endpoint != "" || !slices.Contains(h.AllowedIPs, "10.64.3.0/24") {
		t.Fatalf("home peer %+v", h)
	}
	if !slices.Contains(d.Outer.Routes, "10.64.3.0/24") || !slices.Contains(d.Outer.Routes, "10.64.2.0/24") {
		t.Fatalf("routes %v", d.Outer.Routes)
	}
}

func TestTheRelayForwards(t *testing.T) {
	d, _ := Plan("cp-1", cluster())
	if !d.Forward || d.Relay != "cp-1" {
		t.Fatalf("relay %+v", d)
	}
	// It forwards outer packets only: it has no inner tunnel, so it can't read home ↔ office.
	if d.Inner != nil {
		t.Fatal("the relay has an inner tunnel")
	}
}

func TestBehindNAT(t *testing.T) {
	d, err := Plan("home", cluster())
	if err != nil {
		t.Fatal(err)
	}
	// Dials both public hosts, keeping the NAT mapping open.
	for _, p := range []string{"cp-1", "worker-1"} {
		if pp := peer(d.Outer, p); pp == nil || pp.Endpoint == "" || pp.Keepalive != Keepalive {
			t.Fatalf("%s peer %+v", p, pp)
		}
	}
	// office's outer address is reached through the relay…
	if r := peer(d.Outer, "cp-1"); !slices.Contains(r.AllowedIPs, "10.63.0.4/32") {
		t.Fatalf("relay peer %+v", r)
	}
	if peer(d.Outer, "office") != nil {
		t.Fatal("a direct outer peer between two NAT'd hosts")
	}
	if w := peer(d.Outer, "worker-1"); slices.Contains(w.AllowedIPs, "10.63.0.4/32") {
		t.Fatal("office routed through a host that isn't the relay")
	}
	// …and their traffic, silos included, runs end to end on the inner tunnel.
	if d.Inner == nil || d.Inner.Address != "10.62.0.3/16" || d.Inner.MTU != InnerMTU {
		t.Fatalf("inner %+v", d.Inner)
	}
	o := peer(*d.Inner, "office")
	if o == nil || o.Endpoint != "10.63.0.4:51821" || o.PublicKey != "ipk-office" || !slices.Equal(o.AllowedIPs, []string{"10.62.0.4/32", "10.64.4.0/24"}) {
		t.Fatalf("inner office peer %+v", o)
	}
	if !slices.Contains(d.Inner.Routes, "10.64.4.0/24") || slices.Contains(d.Outer.Routes, "10.64.4.0/24") {
		t.Fatalf("office's silos must go inside: outer %v inner %v", d.Outer.Routes, d.Inner.Routes)
	}
}

func TestHostsNotOnTheMeshYetAreLeftOut(t *testing.T) {
	hs := cluster()
	hs[1].Status.Network.PublicKey = "" // worker-1 hasn't published its key
	d, _ := Plan("cp-1", hs)
	if peer(d.Outer, "worker-1") != nil {
		t.Fatal("a peer without a key")
	}
	if _, err := Plan("new", append(hs, &v1.Host{})); err == nil || !strings.Contains(err.Error(), "no mesh index") {
		t.Fatalf("unknown self: %v", err)
	}
}

func TestOnlyNATHostsNoRelay(t *testing.T) {
	d, _ := Plan("home", []*v1.Host{host("home", 1, "a", true), host("office", 2, "b", true)})
	// (and with two public hosts but no control plane among them, the lowest index relays)
	if d2, _ := Plan("home", []*v1.Host{host("home", 1, "a", true), host("p9", 9, "x", false), host("p5", 5, "y", false)}); d2.Relay != "p5" {
		t.Fatalf("relay %q", d2.Relay)
	}
	if d.Relay != "" || d.Inner != nil || len(d.Outer.Peers) != 0 {
		t.Fatalf("with nobody public there's no way through: %+v", d)
	}
}

func TestAssignIndexes(t *testing.T) {
	a, b, c := &v1.Host{}, &v1.Host{}, &v1.Host{}
	a.Name, b.Name, c.Name = "a", "b", "c"
	b.Status.Network.Index = 1
	got, err := AssignIndexes([]*v1.Host{c, a, b})
	if err != nil || len(got) != 2 || got["a"] != 2 || got["c"] != 3 {
		t.Fatalf("%v %v", got, err)
	}
}
