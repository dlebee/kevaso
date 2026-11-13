package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// A control plane that ran on SQLite restarts with --store etcd: its objects move into the
// embedded etcd member once, and it serves them; a second restart doesn't migrate again.
func TestControlPlaneMovesToEtcd(t *testing.T) {
	data := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "kvcp")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "admin.sock")

	var mu sync.Mutex
	var logs []string
	run := func(storeKind string) (*client.Client, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		r, err := Start(ctx, Config{
			ClusterName: "test", HostName: "cp-1", Address: "127.0.0.1",
			DataDir: data, Listen: "127.0.0.1:0", AdminSocket: sock, Heartbeat: 50 * time.Millisecond,
			Store: storeKind, Etcd: EtcdConfig{ClientListen: "127.0.0.1:0"},
			Log: func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() },
		})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		c := client.NewUnix(sock)
		waitReady(t, c)
		return c, func() {
			cancel()
			if err := r.Wait(); err != nil {
				t.Fatal(err)
			}
		}
	}
	migrations := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range logs {
			if strings.HasPrefix(l, "migrated ") {
				n++
			}
		}
		return n
	}

	c, stop := run(StoreSQLite)
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}}
	if err := c.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	stop()

	c, stop = run(StoreEtcd)
	var got v1.Namespace
	if err := c.Get(context.Background(), "Namespace", "", "dev", &got); err != nil || got.UID != ns.UID {
		t.Fatalf("after the move to etcd: %+v, %v", got.ObjectMeta, err)
	}
	if migrations() != 1 {
		t.Fatalf("%d migrations logged, want 1", migrations())
	}
	if _, err := os.Stat(filepath.Join(data, "store.db")); !os.IsNotExist(err) {
		t.Fatalf("store.db still in place: %v", err)
	}
	stop()

	c, stop = run(StoreEtcd)
	defer stop()
	if err := c.Get(context.Background(), "Namespace", "", "dev", &got); err != nil {
		t.Fatal(err)
	}
	if migrations() != 1 {
		t.Fatalf("migrated again: %d migrations", migrations())
	}
}
