package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"kevaso.com/core/internal/mesh"
	"kevaso.com/core/internal/store"
)

// The cluster's IPv6 range (the IPv6 effort): one random unique local /48, made the first time a
// host needs its silo /64 and stored once, so every leader (and a restore of the store) hands out
// the same /64s. The store's own create-if-absent makes it one: two leaders racing both read the
// one that was stored first.

// ClusterNetworkKind is the store kind of the cluster's network record (one object, Name
// ClusterNetworkName): the control plane's own, not an API kind.
const (
	ClusterNetworkKind = "ClusterNetwork"
	ClusterNetworkName = "cluster"
)

// ClusterNetwork is the stored record.
type ClusterNetwork struct {
	ULA string `json:"ula"` // fdXX:XXXX:XXXX::/48
}

var clusterNetworkKey = store.Key{Kind: ClusterNetworkKind, Name: ClusterNetworkName}

// ReadULA is the cluster's IPv6 /48 as stored ("" if none was made yet).
func ReadULA(ctx context.Context, st store.Store) (string, error) {
	o, err := st.Get(ctx, clusterNetworkKey)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var n ClusterNetwork
	if err := json.Unmarshal(o.Data, &n); err != nil {
		return "", fmt.Errorf("%s: %w", clusterNetworkKey, err)
	}
	p, err := netip.ParsePrefix(n.ULA)
	if err != nil {
		return "", fmt.Errorf("%s: ula %q: %w", clusterNetworkKey, n.ULA, err)
	}
	if err := mesh.CheckULA(p); err != nil {
		return "", fmt.Errorf("%s: %w", clusterNetworkKey, err)
	}
	return p.String(), nil
}

// EnsureULA is the cluster's IPv6 /48: the stored one, or a fresh random one stored now.
func EnsureULA(ctx context.Context, st store.Store) (string, error) {
	if ula, err := ReadULA(ctx, st); err != nil || ula != "" {
		return ula, err
	}
	b, _ := json.Marshal(ClusterNetwork{ULA: mesh.NewULA().String()})
	if _, err := st.Create(ctx, clusterNetworkKey, b); err != nil && !errors.Is(err, store.ErrExists) {
		return "", err
	}
	ula, err := ReadULA(ctx, st) // ours, or the one another leader stored first
	if err == nil && ula == "" {
		err = fmt.Errorf("%s: not stored", clusterNetworkKey)
	}
	return ula, err
}
