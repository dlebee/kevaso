package controlplane

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/backup"
	"kevaso.com/core/internal/kms"
)

// Starting a cluster is always explicit (brainstorm §0.7, audit K-032). A system node keeps a
// record next to its PKI, apart from the store: the cluster it belongs to, and that it was made.

func cpConfig(t *testing.T, data string) Config {
	t.Helper()
	sockDir, _ := os.MkdirTemp("/tmp", "kvcl")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	return Config{ClusterName: "test", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: data, Listen: "127.0.0.1:0", AdminSocket: filepath.Join(sockDir, "admin.sock"), Heartbeat: 50 * time.Millisecond}
}

// up starts cfg and waits for its host to be Ready; the returned func stops it.
func up(t *testing.T, cfg Config) (*Running, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Start(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	waitReady(t, client.NewUnix(cfg.AdminSocket))
	return r, func() { cancel(); _ = r.Wait() }
}

// refused starts cfg, which must fail, and returns the error.
func refused(t *testing.T, cfg Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := Start(ctx, cfg)
	if err == nil {
		cancel()
		_ = r.Wait()
		t.Fatal("the control plane started")
	}
	return err
}

func mustContain(t *testing.T, err error, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refused without saying %q: %v", w, err)
		}
	}
}

func TestANodeWithoutAClusterRecordCreatesNoCluster(t *testing.T) {
	data := t.TempDir()
	err := refused(t, cpConfig(t, data))
	mustContain(t, err, "kvoadm init")
	if _, err := os.Stat(filepath.Join(data, "pki", "ca.key")); err == nil {
		t.Fatal("a CA was made anyway")
	}
	if _, err := os.Stat(filepath.Join(data, "store.db")); err == nil {
		t.Fatal("a store was made anyway")
	}
}

func TestCreateModeWritesTheRecordAndTheStoreIdentity(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create = true
	r, stop := up(t, cfg)
	rec, err := ReadClusterRecord(data)
	if err != nil || rec == nil {
		t.Fatalf("record: %+v %v", rec, err)
	}
	if rec.State != RecordInitialized || rec.ID == "" || rec.Cluster != "test" {
		t.Fatalf("record %+v", rec)
	}
	if r.Cluster.ID != rec.ID || r.Cluster.Epoch != 1 || r.Cluster.History == "" {
		t.Fatalf("identity %+v, record %+v", r.Cluster, rec)
	}
	stop()
	// Restarts are ordinary starts: no create mode, same identity.
	r2, stop2 := up(t, cpConfig(t, data))
	defer stop2()
	if r2.Cluster != r.Cluster {
		t.Fatalf("restart changed the identity: %+v, was %+v", r2.Cluster, r.Cluster)
	}
}

// kevasod admin create-cluster writes a record that asks the next start to create the cluster
// (kvoadm init runs it before installing the unit): the unit itself never carries create mode.
func TestCreateClusterThenAPlainStart(t *testing.T) {
	data := t.TempDir()
	if err := CreateCluster(data, "home", time.Now()); err != nil {
		t.Fatal(err)
	}
	rec, _ := ReadClusterRecord(data)
	if rec == nil || rec.State != RecordNew || rec.Cluster != "home" {
		t.Fatalf("record %+v", rec)
	}
	r, stop := up(t, cpConfig(t, data))
	defer stop()
	rec2, _ := ReadClusterRecord(data)
	if rec2.State != RecordInitialized || rec2.ID != rec.ID || r.Cluster.ID != rec.ID {
		t.Fatalf("record after start %+v (was %+v), identity %+v", rec2, rec, r.Cluster)
	}
	// A second create-cluster on a node that belongs to a cluster changes nothing.
	if err := CreateCluster(data, "home", time.Now()); err != nil {
		t.Fatalf("again: %v", err)
	}
	if rec3, _ := ReadClusterRecord(data); *rec3 != *rec2 {
		t.Fatalf("record rewritten: %+v", rec3)
	}
	if err := CreateCluster(data, "other", time.Now()); err == nil {
		t.Fatal("create-cluster under another name over an existing record")
	}
}

// K-032: the store's data gone while the PKI (and the record with it) survives. Before, this
// booted an empty cluster under the old CA. Create mode doesn't change that: the record says the
// cluster was made, so an empty store is a loss, not a start.
func TestARecordWithAnEmptyStoreRefusesToStart(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create = true
	_, stop := up(t, cfg)
	admin := client.NewUnix(cfg.AdminSocket)
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "keep"}}
	if err := admin.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	stop()
	before, _ := ReadClusterRecord(data)
	for _, f := range []string{"store.db", "store.db-wal", "store.db-shm"} {
		_ = os.Remove(filepath.Join(data, f))
	}
	for _, create := range []bool{false, true} {
		cfg := cpConfig(t, data)
		cfg.Create = create
		err := refused(t, cfg)
		mustContain(t, err, "store", "restore", "kvoadm init")
	}
	if rec, _ := ReadClusterRecord(data); rec == nil || rec.State != RecordInitialized || rec.ID != before.ID {
		t.Fatalf("record changed by the refused starts: %+v, was %+v", rec, before)
	}
}

func TestARecordOfAnotherClusterRefusesToStart(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, d := range []string{a, b} {
		cfg := cpConfig(t, d)
		cfg.Create = true
		_, stop := up(t, cfg)
		stop()
	}
	// b's store under a's PKI and record.
	for _, f := range []string{"store.db", "store.db-wal", "store.db-shm"} {
		_ = os.Remove(filepath.Join(a, f))
		if bs, err := os.ReadFile(filepath.Join(b, f)); err == nil {
			if err := os.WriteFile(filepath.Join(a, f), bs, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	err := refused(t, cpConfig(t, a))
	mustContain(t, err, "another cluster")
}

// The PKI gone while the store survives: no new CA is minted (every certificate in the cluster
// would stop working without a word).
func TestALostPKIIsNotReplaced(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create = true
	_, stop := up(t, cfg)
	stop()
	if err := os.RemoveAll(filepath.Join(data, "pki")); err != nil {
		t.Fatal(err)
	}
	err := refused(t, cpConfig(t, data))
	mustContain(t, err, "CA")
	if _, err := os.Stat(filepath.Join(data, "pki", "ca.key")); err == nil {
		t.Fatal("a new CA was made")
	}
}

// A restore (kevasod admin restore, which kvoadm init --restore runs) keeps the cluster's
// identity and starts a new history: the epoch goes up, so workers can tell a deliberate restore
// from a control plane that lost its data.
func TestARestoredBackupStartsANewHistoryOfTheSameCluster(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create = true
	r, stop := up(t, cfg)
	admin := client.NewUnix(cfg.AdminSocket)
	ctx := context.Background()
	var rk client.RecoveryKey
	if err := admin.Call(ctx, http.MethodPost, "/admin/kms/recovery-key", nil, &rk); err != nil {
		t.Fatal(err)
	}
	ns := &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "kept"}}
	if err := admin.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	var b client.Backup
	if err := admin.Call(ctx, http.MethodPost, "/admin/backup", nil, &b); err != nil {
		t.Fatal(err)
	}
	stop()
	key, err := kms.ParseRecoveryKey(rk.RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir()
	if _, err := backup.Restore(ctx, b.Backup, key, fresh); err != nil {
		t.Fatal(err)
	}
	// Without the mark, a restored data dir is just this cluster's node: same history.
	if err := MarkRestored(fresh); err != nil {
		t.Fatal(err)
	}
	cfg2 := cpConfig(t, fresh)
	r2, stop2 := up(t, cfg2)
	defer stop2()
	if r2.Cluster.ID != r.Cluster.ID || r2.Cluster.Epoch != r.Cluster.Epoch+1 || r2.Cluster.History == r.Cluster.History {
		t.Fatalf("restored identity %+v, was %+v", r2.Cluster, r.Cluster)
	}
	admin2 := client.NewUnix(cfg2.AdminSocket)
	var got v1.Namespace
	if err := admin2.Get(ctx, "Namespace", "", "kept", &got); err != nil {
		t.Fatalf("the restored store: %v", err)
	}
	var gate v1.RestoreGate
	if err := admin2.Get(ctx, "RestoreGate", "", v1.RestoreGateName, &gate); err != nil {
		t.Fatalf("the restore gate: %v", err)
	}
	if gate.Spec.History != r2.Cluster.History || gate.Spec.NoHostsAdded || len(gate.Spec.HostsAdded) != 0 {
		t.Fatalf("a restore with no statement: %+v", gate.Spec)
	}
	if rec, _ := ReadClusterRecord(fresh); rec == nil || rec.State != RecordInitialized || rec.ID != r.Cluster.ID {
		t.Fatalf("record after the restored start %+v", rec)
	}
	// The next start is ordinary: the history stays.
	stop2()
	r3, stop3 := up(t, cpConfig(t, fresh))
	defer stop3()
	if r3.Cluster != r2.Cluster {
		t.Fatalf("a plain restart after the restore moved the history: %+v, was %+v", r3.Cluster, r2.Cluster)
	}
	if err := MarkRestored(t.TempDir()); err == nil {
		t.Fatal("marked a data dir with no restored cluster in it")
	}
}

// The store's data gone on an etcd node (K-032's own case) refuses the same way.
func TestAnEtcdNodeWithLostDataRefusesToStart(t *testing.T) {
	data := t.TempDir()
	cfg := cpConfig(t, data)
	cfg.Create, cfg.Store = true, StoreEtcd
	cfg.Etcd = EtcdConfig{ClientListen: "127.0.0.1:0", UnsafeNoFsync: true}
	_, stop := up(t, cfg)
	stop()
	if err := os.RemoveAll(filepath.Join(data, "etcd", "data")); err != nil {
		t.Fatal(err)
	}
	cfg2 := cpConfig(t, data)
	cfg2.Store, cfg2.Etcd = StoreEtcd, cfg.Etcd
	err := refused(t, cfg2)
	mustContain(t, err, "restore")
	var ce *ClusterError
	if !errors.As(err, &ce) {
		t.Fatalf("not a ClusterError: %T %v", err, err)
	}
}

// Joining system nodes, full and light, take the identity of the cluster they join, keep a record
// of it, and refuse like the first node when they lose their store.
func TestJoinedNodesTakeTheClusterTheyJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("starts three etcd members")
	}
	c := newCluster(t)
	first := c.nodes["cp-1"].run.Cluster
	full, light := c.join("cp-2", false), c.join("cp-3", true)
	for _, n := range []*node{full, light} {
		rec, err := ReadClusterRecord(n.data)
		if err != nil || rec == nil || rec.ID != first.ID || rec.State != RecordInitialized || rec.Cluster != "ha" {
			t.Fatalf("%s: record %+v %v (cluster %+v)", n.name, rec, err, first)
		}
		if n.run.Cluster != first {
			t.Fatalf("%s serves %+v, the cluster is %+v", n.name, n.run.Cluster, first)
		}
	}
	for _, n := range []string{"cp-1", "cp-2", "cp-3"} {
		c.waitHost(c.admin, n, voter)
	}
	light.cancel()
	_ = light.run.Wait()
	if err := os.RemoveAll(filepath.Join(light.data, "etcd")); err != nil {
		t.Fatal(err)
	}
	cfg, _ := c.config("cp-3", true)
	cfg.DataDir, cfg.Store = light.data, StoreEtcd
	err := refused(t, cfg)
	mustContain(t, err, "store is gone", "restore")
}
