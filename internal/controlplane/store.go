package controlplane

import (
	"context"
	"fmt"
	"path/filepath"

	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
)

// Stores the control plane keeps its objects in (Config.Store).
const (
	StoreSQLite = "sqlite" // one file, <data>/store.db: a single control plane (the default)
	StoreEtcd   = "etcd"   // an embedded etcd member under <data>/etcd: the HA store (§4.1)
)

// EtcdConfig is the embedded etcd member, with Store "etcd".
type EtcdConfig struct {
	ClientListen  string // default 127.0.0.1:2379 (this host's control plane only)
	PeerListen    string // "" opens no peer listener: one member
	AdvertisePeer string // what other members dial; "" means PeerListen
}

// cpStore is the control plane's store and what has to close with it.
type cpStore struct {
	store.Store
	snapshot func(ctx context.Context, path string) error
	closers  []func()
}

func (s *cpStore) Snapshot(ctx context.Context, path string) error { return s.snapshot(ctx, path) }

func (s *cpStore) Close() error {
	err := s.Store.Close()
	for _, c := range s.closers {
		c()
	}
	return err
}

// openStore opens the configured store. With etcd, it starts the member and, the first time on a
// data dir that holds a SQLite store, migrates it (once; see store.MigrateSQLite).
func openStore(ctx context.Context, cfg Config, ca *pki.CA) (*cpStore, error) {
	sqlitePath := filepath.Join(cfg.DataDir, "store.db")
	switch cfg.Store {
	case "", StoreSQLite:
		st, err := store.OpenSQLite(sqlitePath, 0)
		if err != nil {
			return nil, err
		}
		return &cpStore{Store: st, snapshot: st.Snapshot}, nil
	case StoreEtcd:
	default:
		return nil, fmt.Errorf("store %q: want %s or %s", cfg.Store, StoreSQLite, StoreEtcd)
	}
	srv, err := etcd.Start(ctx, etcd.Config{
		Name: cfg.HostName, Dir: filepath.Join(cfg.DataDir, "etcd"), CA: ca, Names: []string{cfg.Address},
		ClientListen: cfg.Etcd.ClientListen, PeerListen: cfg.Etcd.PeerListen, AdvertisePeer: cfg.Etcd.AdvertisePeer,
	})
	if err != nil {
		return nil, err
	}
	cli, err := srv.Client()
	if err != nil {
		srv.Close()
		return nil, err
	}
	stop := func() { _ = cli.Close(); srv.Close() }
	st, res, err := store.MigrateSQLite(ctx, cli, sqlitePath, 0)
	if err != nil {
		stop()
		return nil, fmt.Errorf("etcd store: %w", err)
	}
	if res.Ran {
		cfg.Log("migrated %d objects from %s into etcd (revisions continue from %d; watchers re-list)", res.Objects, sqlitePath, res.From)
	}
	return &cpStore{Store: st, snapshot: st.Snapshot, closers: []func(){stop}}, nil
}
