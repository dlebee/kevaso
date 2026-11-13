package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/pki"
)

// A migration that stopped half-way (meta "running", some objects copied, some junk) is refused by
// OpenEtcd and redone from scratch by MigrateSQLite.
func TestInterruptedMigrationIsRedone(t *testing.T) {
	ctx := context.Background()
	ca, _ := pki.NewCA("t", time.Now())
	srv, err := etcd.Start(ctx, etcd.Config{Name: "cp1", Dir: filepath.Join(t.TempDir(), "etcd"), CA: ca, ClientListen: "127.0.0.1:0", UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := srv.Client()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	path := filepath.Join(t.TempDir(), "store.db")
	sq, _ := OpenSQLite(path, 0)
	k := Key{Kind: "Silo", Namespace: "dev", Name: "a"}
	if _, err := sq.Create(ctx, k, []byte(`real`)); err != nil {
		t.Fatal(err)
	}
	_ = sq.Close()

	half := &Etcd{cli: cli, prefix: DefaultEtcdPrefix}
	if err := half.writeMeta(ctx, EtcdMeta{Base: 1, Migration: "running"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Put(ctx, half.objPrefix()+"Silo/dev/junk", "left over"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEtcd(ctx, cli, 0); err == nil {
		t.Fatal("OpenEtcd opened a half-migrated store")
	}
	e, res, err := MigrateSQLite(ctx, cli, path, 0)
	if err != nil || !res.Ran || res.Objects != 1 {
		t.Fatalf("migration %+v, %v", res, err)
	}
	defer func() { _ = e.Close() }()
	objs, _, _ := e.List(ctx, Selector{Kind: "Silo"})
	if len(objs) != 1 || objs[0].Key != k || string(objs[0].Data) != "real" {
		t.Fatalf("after the redo: %+v", objs)
	}
}
