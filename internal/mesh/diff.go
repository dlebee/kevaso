package mesh

import (
	"fmt"
	"net"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Diff turns a wanted interface into the smallest wgctrl change from cur (nil: a new device).
// Peers are updated in place and only removed when they're gone: never ReplacePeers, which drops
// every live session for ~15s (E023). Unchanged peers aren't touched. Pure.
func Diff(want Iface, priv wgtypes.Key, cur *wgtypes.Device) (wgtypes.Config, bool, error) {
	cfg := wgtypes.Config{}
	changed := false
	if cur == nil || cur.PrivateKey != priv {
		cfg.PrivateKey = &priv
		changed = true
	}
	if cur == nil || cur.ListenPort != want.ListenPort {
		p := want.ListenPort
		cfg.ListenPort = &p
		changed = true
	}
	have := map[wgtypes.Key]wgtypes.Peer{}
	if cur != nil {
		for _, p := range cur.Peers {
			have[p.PublicKey] = p
		}
	}
	wanted := map[wgtypes.Key]bool{}
	for _, p := range want.Peers {
		pk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return cfg, false, fmt.Errorf("peer %s: %w", p.Host, err)
		}
		wanted[pk] = true
		pc := wgtypes.PeerConfig{PublicKey: pk, ReplaceAllowedIPs: true}
		for _, a := range p.AllowedIPs {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				return cfg, false, fmt.Errorf("peer %s: %w", p.Host, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *n)
		}
		if p.Endpoint != "" {
			ep, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return cfg, false, fmt.Errorf("peer %s: %w", p.Host, err)
			}
			pc.Endpoint = ep
		}
		ka := time.Duration(p.Keepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka
		if old, ok := have[pk]; ok && same(old, pc) {
			continue
		}
		cfg.Peers = append(cfg.Peers, pc)
		changed = true
	}
	for pk := range have {
		if !wanted[pk] {
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{PublicKey: pk, Remove: true})
			changed = true
		}
	}
	return cfg, changed, nil
}

func same(old wgtypes.Peer, want wgtypes.PeerConfig) bool {
	if want.Endpoint != nil && (old.Endpoint == nil || old.Endpoint.String() != want.Endpoint.String()) {
		return false // (no wanted endpoint: keep whatever WireGuard learned)
	}
	if old.PersistentKeepaliveInterval != *want.PersistentKeepaliveInterval {
		return false
	}
	a, b := make([]string, 0, len(old.AllowedIPs)), make([]string, 0, len(want.AllowedIPs))
	for _, n := range old.AllowedIPs {
		a = append(a, n.String())
	}
	for _, n := range want.AllowedIPs {
		b = append(b, n.String())
	}
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
