package kvoadm

import (
	"context"
	"encoding/json"
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
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/secrets"
	"kevaso.com/core/internal/store"
)

func installed(o InitOptions) string { return Unit(o) }

func TestInitKeepsTheExistingUnit(t *testing.T) {
	old := installed(InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", Worker: true,
		Runtimes: []string{"docker"}, Store: "etcd", LoopStorage: "40G", EgressExtraCA: "/etc/kevaso/extra.pem"})
	o := InitOptions{Name: "cp", InternalIP: "10.1.0.9", Cluster: "c"}
	got, unit, err := MergeUnit(old, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--worker", "--runtime docker", "--store etcd", "--loop-size 40G", "--egress-extra-ca /etc/kevaso/extra.pem", "--internal-ip 10.1.0.9"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lost %s:\n%s", want, unit)
		}
	}
	if !got.Worker || got.Store != "etcd" || got.LoopStorage != "40G" {
		t.Fatalf("options: %+v", got)
	}
	// A new loop size of the same mode is this run's, and is kept.
	o.LoopStorage = "80G"
	_, unit, err = MergeUnit(old, o)
	if err != nil || !strings.Contains(unit, "--loop-size 80G") || strings.Contains(unit, "--loop-size 40G") {
		t.Fatalf("loop size: %v\n%s", err, unit)
	}
}

func TestInitRefusesToDropTheExistingUnit(t *testing.T) {
	old := installed(InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", Worker: true,
		Runtimes: []string{"cloud-hypervisor"}, Store: "etcd", LoopStorage: "40G"})
	o := InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", Worker: true, Runtimes: []string{"docker"}}
	if _, unit, err := MergeUnit(old, o); err == nil || !strings.Contains(err.Error(), "cloud-hypervisor") || unit != "" {
		t.Fatalf("runtime drop: %v %q", err, unit)
	}
	o = InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", Worker: true, Runtimes: []string{"cloud-hypervisor"}, StorageDevice: "/dev/sdb", storeGiven: true, Store: ""}
	if _, _, err := MergeUnit(old, o); err == nil || !strings.Contains(err.Error(), "--loop-storage") {
		t.Fatalf("storage mode: %v", err)
	}
	o = InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", Worker: true, Runtimes: []string{"cloud-hypervisor"}, LoopStorage: "40G", storeGiven: true}
	if _, _, err := MergeUnit(old, o); err == nil || !strings.Contains(err.Error(), "--store etcd") {
		t.Fatalf("store: %v", err)
	}
	o = InitOptions{Name: "cp", InternalIP: "10.0.0.5", Cluster: "c", ReplaceUnit: true}
	_, unit, err := MergeUnit(old, o)
	if err != nil || strings.Contains(unit, "--worker") || strings.Contains(unit, "--store etcd") {
		t.Fatalf("replace: %v\n%s", err, unit)
	}
}

func TestParseInitReplaceUnit(t *testing.T) {
	o, err := parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b", "--replace-unit", "--store", "etcd"})
	if err != nil || !o.ReplaceUnit || !o.storeGiven || o.Store != "etcd" {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = parseInit([]string{"root@10.0.0.5", "--ssh-key", "k", "--kevasod", "b"})
	if err != nil || o.ReplaceUnit || o.storeGiven || o.Store != "" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestRestoreFillsTheWorkerFromTheHost(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	ca, err := pki.NewCA("c", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(filepath.Join(dir, "pki")); err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(dir, "store.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "cp-1"},
		Spec:   v1.HostSpec{Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}, {Name: "cloud-hypervisor"}}}}},
		Status: v1.HostStatus{ControlPlane: &v1.ControlPlaneStatus{Store: "etcd"}}}
	b, _ := json.Marshal(h)
	if _, err := st.Create(ctx, store.Key{Kind: "Host", Name: "cp-1"}, b); err != nil {
		t.Fatal(err)
	}
	k, err := kms.OpenLocal(filepath.Join(dir, "kms", "local.json"))
	if err != nil {
		t.Fatal(err)
	}
	rk := kms.NewRecoveryKey()
	pub, _ := rk.Public()
	esc, _ := k.EscrowKeys(pub)
	if err := secrets.SaveEscrow(ctx, st, esc); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	ks, _ := k.Status(ctx)
	blob, err := backup.Make(ctx, dir, func(ctx context.Context, path string) error {
		in, err := os.ReadFile(filepath.Join(dir, "store.db"))
		if err != nil {
			return err
		}
		return os.WriteFile(path, in, 0o600)
	}, backup.Manifest{Cluster: "prod", Host: "cp-1", Created: time.Now(), KMSKeyID: ks.KeyID}, pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(client.RestoreRequest{Backup: blob, RecoveryKey: rk.String()})
	o, err := (InitOptions{Name: "cp-1"}).withRestoredHost(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !o.Worker || o.Store != "etcd" || strings.Join(o.Runtimes, ",") != "docker,cloud-hypervisor" {
		t.Fatalf("%+v", o)
	}
	if _, err := (InitOptions{Name: "missing"}).withRestoredHost(raw); err == nil {
		t.Fatal("a backup with no such host was accepted")
	}
	o, err = (InitOptions{Name: "missing", ReplaceUnit: true}).withRestoredHost(raw)
	if err != nil || o.Worker {
		t.Fatalf("replace: %+v %v", o, err)
	}
}
