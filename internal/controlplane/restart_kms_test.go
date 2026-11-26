package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// The master key's file gone while the store still holds what it sealed (a restore killed
// between writing the store and rebuilding the key, a key file lost by hand): the control plane
// made a new master key without a word, no secret it held opened again, and what it sealed from
// then on was under a key no backup's escrow has. It must refuse to start instead.
func TestAControlPlaneWithSealedDataButNoMasterKeyRefusesToStart(t *testing.T) {
	data := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "kvcp")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "admin.sock")
	r, stop := start(t, data, sock)
	admin := client.NewUnix(sock)
	waitReady(t, admin)
	ctx := context.Background()
	_ = admin.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "web3"}})
	sec := &v1.Secret{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "web3"}}
	sec.Spec.Data = map[string][]byte{"password": []byte("hunter2")}
	if err := admin.Create(ctx, sec); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(data, "kms", "local.json")); err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r2, err := Start(sctx, Config{ClusterName: "test", HostName: "cp-1", InternalIP: "127.0.0.1",
		DataDir: data, Listen: "127.0.0.1:0", AdminSocket: sock, Heartbeat: 50 * time.Millisecond})
	if err == nil {
		cancel()
		_ = r2.Wait()
		t.Fatal("started with a new master key over sealed secrets")
	}
	if !strings.Contains(err.Error(), "master key") {
		t.Fatalf("refused, but not saying why: %v", err)
	}
	if _, err := os.Stat(filepath.Join(data, "kms", "local.json")); err == nil {
		t.Fatal("a new key file was made anyway")
	}
}
