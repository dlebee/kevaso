package integration

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controlplane"
	"kevaso.com/core/internal/mesh"
)

// Every host runs the mesh agent: indexes are handed out once, each publishes its keys, and the
// plans they compute agree (who dials whom, the one relay, the end-to-end tunnel between NAT'd
// hosts). The kernel side is recorded instead of applied.
func TestMeshPlansAgree(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir, _ := os.MkdirTemp("/tmp", "kvm")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if _, err := controlplane.Start(ctx, controlplane.Config{ClusterName: "it", HostName: "cp-1", ExternalIP: "203.0.113.10",
		DataDir: filepath.Join(dir, "cp"), Listen: "127.0.0.1:0", AdminSocket: filepath.Join(dir, "a.sock"), Heartbeat: 100 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	admin := client.NewUnix(filepath.Join(dir, "a.sock"))
	for _, h := range []struct {
		name, addr string
		nat        bool
	}{{"worker-1", "198.51.100.30", false}, {"home", "192.168.1.20", true}, {"office", "192.168.2.20", true}} {
		if err := admin.Create(ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: h.name},
			Spec: v1.HostSpec{InternalIP: h.addr, Network: v1.HostNetwork{BehindNAT: h.nat}, Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	plans := map[string]mesh.Desired{}
	for _, name := range []string{"cp-1", "worker-1", "home", "office"} {
		a := &mesh.Agent{Client: admin, HostName: name, Dir: filepath.Join(dir, "mesh-"+name),
			Apply: func(d mesh.Desired, _, _ wgtypes.Key) error { mu.Lock(); plans[name] = d; mu.Unlock(); return nil }}
		go func() { _ = a.Run(ctx) }()
	}
	// Converged: every host sees all three others (directly or end to end).
	complete := func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, name := range []string{"cp-1", "worker-1", "home", "office"} {
			d, ok := plans[name]
			if !ok {
				return false
			}
			n := len(d.Outer.Peers)
			if d.Inner != nil {
				n += len(d.Inner.Peers)
			}
			if n != 3 {
				return false
			}
		}
		return true
	}
	for !complete() {
		select {
		case <-ctx.Done():
			mu.Lock()
			t.Fatalf("mesh didn't converge: %+v", plans)
		case <-time.After(50 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	indexes := map[string]bool{}
	for name, d := range plans {
		if indexes[d.Outer.Address] {
			t.Fatalf("two hosts share %s", d.Outer.Address)
		}
		indexes[d.Outer.Address] = true
		t.Logf("%s: %s", name, d.Outer.Address)
		if d.Relay != "cp-1" {
			t.Errorf("%s uses relay %q", name, d.Relay)
		}
	}
	if !plans["cp-1"].Forward || plans["worker-1"].Forward {
		t.Error("only cp-1 (the lowest-index public host) relays")
	}
	if plans["home"].Inner == nil || plans["home"].Inner.Peers[0].Host != "office" || plans["office"].Inner.Peers[0].Host != "home" {
		t.Fatalf("home ↔ office isn't end to end: %+v %+v", plans["home"].Inner, plans["office"].Inner)
	}
	// The private keys stayed on the "hosts" (0600), only public keys were published.
	if fi, err := os.Stat(filepath.Join(dir, "mesh-home", "kevaso0.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
}
