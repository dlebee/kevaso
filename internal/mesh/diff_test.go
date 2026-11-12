package mesh

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func key(t *testing.T) wgtypes.Key {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDiff(t *testing.T) {
	priv := key(t)
	a, b, gone := key(t).PublicKey(), key(t).PublicKey(), key(t).PublicKey()
	want := Iface{ListenPort: 51820, Peers: []Peer{
		{Host: "a", PublicKey: a.String(), Endpoint: "203.0.113.10:51820", AllowedIPs: []string{"10.63.0.1/32", "10.64.1.0/24"}},
		{Host: "b", PublicKey: b.String(), AllowedIPs: []string{"10.63.0.2/32"}, Keepalive: 25},
	}}
	// A new device: key, port, both peers.
	cfg, changed, err := Diff(want, priv, nil)
	if err != nil || !changed || cfg.PrivateKey == nil || *cfg.ListenPort != 51820 || len(cfg.Peers) != 2 || cfg.ReplacePeers {
		t.Fatalf("new: %+v %v %v", cfg, changed, err)
	}
	// The device as it is now: a matches, b's allowed IPs changed, and a third peer is gone.
	_, n1, _ := net.ParseCIDR("10.63.0.1/32")
	_, n2, _ := net.ParseCIDR("10.64.1.0/24")
	_, n3, _ := net.ParseCIDR("10.63.0.9/32")
	ep, _ := net.ResolveUDPAddr("udp", "203.0.113.10:51820")
	learned, _ := net.ResolveUDPAddr("udp", "198.51.100.77:40000")
	cur := &wgtypes.Device{PrivateKey: priv, ListenPort: 51820, Peers: []wgtypes.Peer{
		{PublicKey: a, Endpoint: ep, AllowedIPs: []net.IPNet{*n2, *n1}},
		{PublicKey: b, Endpoint: learned, AllowedIPs: []net.IPNet{*n3}, PersistentKeepaliveInterval: 25 * time.Second},
		{PublicKey: gone},
	}}
	cfg, changed, _ = Diff(want, priv, cur)
	if !changed || cfg.PrivateKey != nil || cfg.ListenPort != nil || cfg.ReplacePeers {
		t.Fatalf("update: %+v", cfg)
	}
	got := map[wgtypes.Key]wgtypes.PeerConfig{}
	for _, p := range cfg.Peers {
		got[p.PublicKey] = p
	}
	if _, touched := got[a]; touched {
		t.Error("an unchanged peer was rewritten (its session would be disturbed for nothing)")
	}
	if p := got[b]; !p.ReplaceAllowedIPs || len(p.AllowedIPs) != 1 || p.AllowedIPs[0].String() != "10.63.0.2/32" || p.Endpoint != nil {
		t.Errorf("b: %+v (and its learned endpoint must be kept)", p)
	}
	if p := got[gone]; !p.Remove {
		t.Error("a peer that's gone wasn't removed")
	}
	// Nothing to do.
	cur.Peers = cur.Peers[:1]
	cur.Peers = append(cur.Peers, wgtypes.Peer{PublicKey: b, Endpoint: learned, AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 63, 0, 2).To4(), Mask: net.CIDRMask(32, 32)}}, PersistentKeepaliveInterval: 25 * time.Second})
	if _, changed, _ = Diff(want, priv, cur); changed {
		t.Error("no change reported as a change")
	}
}
