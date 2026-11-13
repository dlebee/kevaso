package store

import (
	"context"
	"errors"
	"fmt"
	"os"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// MigratedSuffix is added to a SQLite store's file name once it migrated into etcd: it stays as a
// copy, but nothing opens it as the store again.
const MigratedSuffix = ".migrated"

// Migration says what MigrateSQLite did.
type Migration struct {
	Ran     bool  // false: the store had migrated before (or there was nothing to migrate)
	Objects int   // objects copied
	From    int64 // the SQLite store's revision, now the etcd store's Base
}

// migrateBatch is how many objects go in one etcd transaction (etcd allows 128 operations).
const migrateBatch = 100

// MigrateSQLite moves the SQLite store at path into the etcd cluster behind cli, once, and opens
// the etcd store. Run it before the control plane serves.
//
// It copies every object in key order (kind, namespace, name), 100 to a transaction, with its
// bytes unchanged. etcd gives the objects new revisions; what keeps informers correct is that
// Kevaso's revisions only move forward (the etcd store's Base is the SQLite store's last
// revision, so every migrated object's resource version is above any the clients saw), and that
// a watch from any revision before the migration is ErrCompacted: every watcher re-lists (E021),
// and since every resource version changed, every informer reports every object once.
//
// The meta record in etcd says the migration is running, then done; a migration interrupted
// half-way is wiped and redone on the next start, and a finished one never runs again. Then the
// SQLite file is renamed with MigratedSuffix. If path doesn't exist, it opens the etcd store.
func MigrateSQLite(ctx context.Context, cli *clientv3.Client, path string, keep int) (*Etcd, Migration, error) {
	return migrateSQLite(ctx, cli, DefaultEtcdPrefix, path, keep)
}

func migrateSQLite(ctx context.Context, cli *clientv3.Client, prefix, path string, keep int) (*Etcd, Migration, error) {
	var res Migration
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		e, err := openEtcd(ctx, cli, prefix, keep, false)
		return e, res, err
	}
	probe := &Etcd{cli: cli, prefix: prefix}
	m, ok, err := probe.readMeta(ctx)
	if err != nil {
		return nil, res, err
	}
	switch {
	case ok && m.Migration == "done":
		// Migrated before; the rename didn't happen (a crash right after). Finish that.
		if err := retire(path); err != nil {
			return nil, res, err
		}
		e, err := openEtcd(ctx, cli, prefix, keep, false)
		return e, res, err
	case ok && m.Migration == "":
		return nil, res, fmt.Errorf("%s holds a SQLite store, and etcd already holds one that didn't come from it: refusing to choose; move one away", path)
	}

	src, err := OpenSQLite(path, 0)
	if err != nil {
		return nil, res, err
	}
	objs, rev, err := src.all(ctx)
	if cerr := src.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, res, fmt.Errorf("reading %s: %w", path, err)
	}
	// Start (or start over): wipe what a half-done migration left, then say it's running.
	if _, err := cli.Delete(ctx, probe.objPrefix(), clientv3.WithPrefix()); err != nil {
		return nil, res, err
	}
	m = EtcdMeta{Base: rev, Migration: "running", MigratedFrom: path}
	if err := probe.writeMeta(ctx, m); err != nil {
		return nil, res, err
	}
	e, err := openEtcd(ctx, cli, prefix, keep, true)
	if err != nil {
		return nil, res, err
	}
	fail := func(err error) (*Etcd, Migration, error) { _ = e.Close(); return nil, res, err }
	for i := 0; i < len(objs); i += migrateBatch {
		var ops []clientv3.Op
		for _, o := range objs[i:min(i+migrateBatch, len(objs))] {
			k, err := e.key(o.Key)
			if err != nil {
				return fail(fmt.Errorf("migrating %s: %w", o.Key, err))
			}
			ops = append(ops, clientv3.OpPut(k, string(o.Data)))
		}
		if _, err := cli.Txn(ctx).Then(ops...).Commit(); err != nil {
			return fail(fmt.Errorf("migrating objects %d..%d: %w", i, i+len(ops)-1, err))
		}
	}
	m.Migration, m.MigratedObjects = "done", len(objs)
	if err := e.writeMeta(ctx, m); err != nil {
		return fail(err)
	}
	// No watch may replay the copy as history: everything before now is compacted.
	cur, err := e.etcdRevision(ctx)
	if err != nil {
		return fail(err)
	}
	if _, err := cli.Compact(ctx, cur-e.base); err != nil {
		return fail(fmt.Errorf("compacting after the migration: %w", err))
	}
	if err := retire(path); err != nil {
		return fail(err)
	}
	return e, Migration{Ran: true, Objects: len(objs), From: rev}, nil
}

// retire renames a migrated SQLite store (and any WAL files) out of the way.
func retire(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Rename(p, p+MigratedSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
