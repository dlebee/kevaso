package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"kevaso.com/core/internal/etcd"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/store/storetest"
)

// newEtcd starts a one-member etcd on loopback (TLS from a fresh CA) and returns a client of it;
// both end with the test.
func newEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := etcd.Start(context.Background(), etcd.Config{Name: "cp1", Dir: filepath.Join(t.TempDir(), "etcd"), CA: ca,
		ClientListen: "127.0.0.1:0", UnsafeNoFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := srv.Client()
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close(); srv.Close() })
	return cli
}

func openEtcd(t *testing.T, cli *clientv3.Client, keep int) *store.Etcd {
	t.Helper()
	s, err := store.OpenEtcd(context.Background(), cli, keep)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEtcd(t *testing.T) {
	storetest.Run(t, func(t *testing.T, keep int) store.Store { return openEtcd(t, newEtcd(t), keep) })
}

// Two stores on one etcd (two control planes on one cluster) see each other's writes, live.
func TestEtcdTwoStoresOneCluster(t *testing.T) {
	ctx := context.Background()
	cli := newEtcd(t)
	a, b := openEtcd(t, cli, 0), openEtcd(t, cli, 0)
	defer func() { _ = a.Close(); _ = b.Close() }()
	rev, _ := b.Revision(ctx)
	ch, err := b.Watch(ctx, store.Selector{Kind: "Silo"}, rev)
	if err != nil {
		t.Fatal(err)
	}
	k := store.Key{Kind: "Silo", Namespace: "dev", Name: "x/y"} // a name may hold '/'
	o, err := a.Create(ctx, k, []byte(`1`))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-ch:
		if ev.Type != store.Added || ev.Object.Key != k || ev.Object.Revision != o.Revision {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	if _, err := b.Update(ctx, k, []byte(`2`), o.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Update(ctx, k, []byte(`3`), o.Revision); err == nil {
		t.Fatal("a stale update through the other store succeeded")
	}
	if _, err := a.Create(ctx, store.Key{Kind: "Silo", Namespace: "a/b", Name: "c"}, nil); err == nil {
		t.Fatal("a namespace with '/' was accepted")
	}
}
