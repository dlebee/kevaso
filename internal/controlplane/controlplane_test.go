package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func start(t *testing.T, dataDir, sock string) (*Running, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Start(ctx, Config{
		ClusterName: "test", HostName: "cp-1", Address: "127.0.0.1",
		DataDir: dataDir, Listen: "127.0.0.1:0", AdminSocket: sock, Heartbeat: 50 * time.Millisecond,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return r, cancel
}

func waitReady(t *testing.T, c *client.Client) v1.Host {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		var h v1.Host
		if err := c.Get(ctx, "Host", "", "cp-1", &h); err == nil && meta.IsTrue(h.Status.Conditions, "Ready") && h.Status.LastHeartbeat != nil {
			return h
		}
		select {
		case <-ctx.Done():
			t.Fatal("host never became Ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestControlPlaneComesUpReadyAndIssuesAdminCredentials(t *testing.T) {
	data := t.TempDir()
	sockDir, _ := os.MkdirTemp("/tmp", "kvcp")
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "admin.sock")

	r, stop := start(t, data, sock)
	admin := client.NewUnix(sock)
	h := waitReady(t, admin)
	if h.Spec.Components.ControlPlane == nil || h.Spec.Address != "127.0.0.1" {
		t.Fatalf("registered host %+v", h.Spec)
	}

	// Credentials for kvo: key made here, only the CSR goes to the socket.
	key, csr, err := client.NewKeyAndCSR("david")
	if err != nil {
		t.Fatal(err)
	}
	cert, ca, err := admin.SignUserCSR(context.Background(), "david", csr)
	if err != nil {
		t.Fatal(err)
	}
	kvo, err := client.NewTLS("https://"+r.APIAddr, ca, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, kvo) // the same answer over TLS with the minted certificate

	// The silo controller runs: with no worker in the cluster, a silo waits and says why.
	ctx := context.Background()
	_ = kvo.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor"}}
	if err := kvo.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got v1.Silo
		_ = kvo.Get(ctx, "Silo", "dev", "web", &got)
		if c := meta.FindCondition(got.Status.Conditions, "Scheduled"); c != nil && c.Reason == "Unschedulable" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("silo controller didn't act: %+v", got.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Restart: same CA, same data.
	stop()
	if err := r.Wait(); err != nil {
		t.Fatal(err)
	}
	r2, stop2 := start(t, data, sock)
	defer func() { stop2(); _ = r2.Wait() }()
	if !r2.CA.Cert.Equal(r.CA.Cert) {
		t.Fatal("restart created a new CA: every certificate would be invalid")
	}
	kvo2, _ := client.NewTLS("https://"+r2.APIAddr, ca, cert, key)
	waitReady(t, kvo2)
	if fi, err := os.Stat(filepath.Join(data, "pki", "ca.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode: %v %v", fi.Mode(), err)
	}
}

func TestStartValidates(t *testing.T) {
	if _, err := Start(context.Background(), Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}
