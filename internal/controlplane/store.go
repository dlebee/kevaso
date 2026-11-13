package controlplane

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

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
	// Join and InitialCluster: a member joining an existing cluster (set from Config.Join's answer).
	Join           bool
	InitialCluster map[string]string
	// UnsafeNoFsync skips fsync: tests only.
	UnsafeNoFsync bool
}

// cpStore is the control plane's store and what has to close with it.
type cpStore struct {
	store.Store
	snapshot func(ctx context.Context, path string) error
	closers  []func()
	etcd     *etcd.Server // the member, with Store "etcd"
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
		Name: cfg.HostName, Dir: filepath.Join(cfg.DataDir, "etcd"), CA: ca, Names: cfg.ips(),
		ClientListen: cfg.Etcd.ClientListen, PeerListen: cfg.Etcd.PeerListen, AdvertisePeer: cfg.Etcd.AdvertisePeer,
		Join: cfg.Etcd.Join, InitialCluster: cfg.Etcd.InitialCluster, UnsafeNoFsync: cfg.Etcd.UnsafeNoFsync,
	})
	if err != nil {
		return nil, err
	}
	// A joining member is a learner first: it serves no reads until the leader's member controller
	// promotes it, once it has caught up (systemnodes.go).
	if srv.IsLearner() {
		cfg.Log("etcd: joined as a learner; waiting to be promoted")
		if err := srv.WaitVoter(ctx, 200*time.Millisecond); err != nil {
			srv.Close()
			return nil, err
		}
		cfg.Log("etcd: promoted to a voter")
	}
	rctx, stopRotation := context.WithCancel(context.Background())
	go srv.RunRotation(rctx, cfg.Clock.Now, 12*time.Hour, cfg.Log)
	cli, err := srv.Client()
	if err != nil {
		stopRotation()
		srv.Close()
		return nil, err
	}
	stop := func() { stopRotation(); _ = cli.Close(); srv.Close() }
	st, res, err := store.MigrateSQLite(ctx, cli, sqlitePath, 0)
	if err != nil {
		stop()
		return nil, fmt.Errorf("etcd store: %w", err)
	}
	if res.Ran {
		cfg.Log("migrated %d objects from %s into etcd (revisions continue from %d; watchers re-list)", res.Objects, sqlitePath, res.From)
	}
	return &cpStore{Store: st, snapshot: st.Snapshot, closers: []func(){stop}, etcd: srv}, nil
}
