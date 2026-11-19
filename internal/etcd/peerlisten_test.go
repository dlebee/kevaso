package etcd

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/internal/pki"
)

func TestPeerListenHosts(t *testing.T) {
	listen, advertise := "10.0.0.1:2380", "203.0.113.10:2380"
	nat := peerListenHosts(listen, advertise, func(string) bool { return false })
	if len(nat) != 1 || nat[0] != listen {
		t.Fatalf("under NAT, peers are dialed on an address that is not on this machine: %v", nat)
	}
	both := peerListenHosts(listen, advertise, func(host string) bool { return host == "203.0.113.10" })
	if len(both) != 2 || both[0] != listen || both[1] != advertise {
		t.Fatalf("a reach address on this machine is not listened on: %v", both)
	}
	same := peerListenHosts(listen, listen, func(string) bool { return true })
	if len(same) != 1 || same[0] != listen {
		t.Fatalf("one address bound twice: %v", same)
	}
	wild := peerListenHosts(listen, "0.0.0.0:2380", func(string) bool { return true })
	if len(wild) != 1 || wild[0] != listen {
		t.Fatalf("a wildcard reach address is bound: %v", wild)
	}
}

func TestStartBindsALocalReachAddressAndNotARemoteOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ca, err := pki.NewCA("c", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	natListen, natReach := freePort(t), freePort(t)
	nat, err := Start(ctx, Config{
		Name: "cp1", Dir: filepath.Join(t.TempDir(), "etcd"), CA: ca,
		ClientListen: "127.0.0.1:0", PeerListen: natListen, AdvertisePeer: natReach,
		UnsafeNoFsync: true, local: func(string) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nat.Close()
	if nat.PeerURL != "https://"+natReach {
		t.Fatalf("advertised %s, want the reach address", nat.PeerURL)
	}
	if len(nat.Etcd.Peers) != 1 {
		t.Fatalf("under NAT the member listens on %d peer addresses", len(nat.Etcd.Peers))
	}
	listen, reach := freePort(t), freePort(t)
	home, err := Start(ctx, Config{
		Name: "cp1", Dir: filepath.Join(t.TempDir(), "etcd"), CA: ca,
		ClientListen: "127.0.0.1:0", PeerListen: listen, AdvertisePeer: reach,
		UnsafeNoFsync: true, local: func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer home.Close()
	if home.PeerURL != "https://"+reach {
		t.Fatalf("advertised %s, want the reach address", home.PeerURL)
	}
	if len(home.Etcd.Peers) != 2 {
		t.Fatalf("a local reach address is not listened on: %d peer listeners", len(home.Etcd.Peers))
	}
}
