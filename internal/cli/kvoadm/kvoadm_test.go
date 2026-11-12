package kvoadm

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

func TestParseInit(t *testing.T) {
	o, err := parseInit([]string{"ubuntu@203.0.113.10", "--kevasod", "/k", "--ssh-port", "2222", "--name", "cp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if o.User != "ubuntu" || o.Address != "203.0.113.10" || o.SSHPort != 2222 || o.Name != "cp-1" || o.Kevasod != "/k" {
		t.Fatalf("parsed %+v", o)
	}
	o, _ = parseInit([]string{"203.0.113.10", "--kevasod", "/k"})
	if o.User != "root" || o.Name != "203-0-113-10" {
		t.Fatalf("defaults: %+v", o)
	}
	for _, bad := range [][]string{{}, {"a", "b", "--kevasod", "/k"}, {"a"}, {"a", "--kevasod", "/k", "--bogus"}, {"a", "--ssh-port", "x", "--kevasod", "/k"}} {
		if _, err := parseInit(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// minimalELF writes just enough of an ELF64 header for debug/elf to read the machine.
func minimalELF(t *testing.T, machine uint16) string {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(h[16:], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(h[18:], machine)
	binary.LittleEndian.PutUint32(h[20:], 1)  // version
	binary.LittleEndian.PutUint16(h[52:], 64) // ehsize
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, h, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestElfArch(t *testing.T) {
	for machine, want := range map[uint16]string{62: "x86_64", 183: "aarch64"} {
		if got, err := ElfArch(minimalELF(t, machine)); err != nil || got != want {
			t.Errorf("machine %d: %q, %v", machine, got, err)
		}
	}
	if _, err := ElfArch(minimalELF(t, 3)); err == nil {
		t.Error("i386 accepted")
	}
	p := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(p, []byte("#!/bin/sh"), 0o755)
	if _, err := ElfArch(p); err == nil {
		t.Error("a script accepted as a binary")
	}
}

func TestSigningKeyIsStableAndVerifies(t *testing.T) {
	dir := t.TempDir()
	k1, pub1, err := SigningKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, pub2, _ := SigningKey(dir)
	if !k1.Equal(k2) || string(pub1) != string(pub2) {
		t.Fatal("a second call made a new key")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "signing.key")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("signing.key mode %v", fi.Mode().Perm())
	}
	// What the host pins is a PKIX public key (openssl pkeyutl reads it), and it verifies the signature.
	blk, _ := pem.Decode(pub1)
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("kevasod binary")
	if !ed25519.Verify(pk.(ed25519.PublicKey), msg, ed25519.Sign(k1, msg)) {
		t.Fatal("signature doesn't verify with the pinned key")
	}
}

func TestSSHKeyIsStable(t *testing.T) {
	dir := t.TempDir()
	s1, pub1, err := SSHKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2, pub2, _ := SSHKey(dir)
	if string(s1.PublicKey().Marshal()) != string(s2.PublicKey().Marshal()) || string(pub1) != string(pub2) {
		t.Fatal("a second call made a new key")
	}
	if !strings.HasPrefix(string(pub1), "ssh-ed25519 ") {
		t.Fatalf("authorized key line %q", pub1)
	}
}

func TestUnitWithWorker(t *testing.T) {
	u := Unit(InitOptions{Name: "hv1", Address: "a", Cluster: "c", Worker: true, LoopStorage: "40G"})
	if !strings.Contains(u, "--worker --runtime cloud-hypervisor --loop-storage /var/lib/kevaso-storage.img --loop-size 40G") {
		t.Fatalf("unit:\n%s", u)
	}
	if strings.Contains(Unit(InitOptions{Name: "hv1", Address: "a", Cluster: "c"}), "--worker") {
		t.Fatal("worker installed without --worker")
	}
}

func TestUnit(t *testing.T) {
	u := Unit(InitOptions{Name: "cp-1", Address: "203.0.113.10", Cluster: "home"})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevasod control-plane --name cp-1 --address 203.0.113.10 --cluster home",
		"Restart=always", "RuntimeDirectory=kevaso", "StateDirectoryMode=0700", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q", want)
		}
	}
}

func TestParseHostAdd(t *testing.T) {
	o, err := parseHostAdd([]string{"root@198.51.100.30", "--name", "worker-1", "--install", "worker", "--label", "gpu=no",
		"--region", "ca-central", "--zone", "tor", "--kevasod", "/k", "--address", "10.0.0.5", "--server", "https://10.0.0.1:6443"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "worker-1" || o.Address != "198.51.100.30" || o.Advertise != "10.0.0.5" || o.Region != "ca-central" || o.Zone != "tor" ||
		o.Labels["gpu"] != "no" || o.ServerForIt != "https://10.0.0.1:6443" || len(o.Runtimes) != 1 || o.Runtimes[0] != "cloud-hypervisor" {
		t.Fatalf("parsed %+v", o)
	}
	if _, err := parseHostAdd([]string{"h", "--install", "control-plane", "--kevasod", "/k"}); err == nil {
		t.Error("control-plane install accepted")
	}
	u := WorkerUnit(o, "https://10.0.0.1:6443")
	if !strings.Contains(u, "ExecStart=/usr/local/bin/kevasod worker --name worker-1 --server https://10.0.0.1:6443 --runtime cloud-hypervisor") {
		t.Fatalf("unit:\n%s", u)
	}
	if strings.Contains(u, "RuntimeDirectory") { // a worker has no admin socket
		t.Fatal("worker unit makes a runtime directory")
	}
}

func TestUnitAdvertisesAnotherAddress(t *testing.T) {
	u := Unit(InitOptions{Name: "cp-1", Address: "127.0.0.1", Advertise: "192.168.105.2", Cluster: "c"})
	if !strings.Contains(u, "--address 192.168.105.2 --cluster c --extra-name 127.0.0.1") {
		t.Fatalf("unit:\n%s", u)
	}
}

func TestDrainPlan(t *testing.T) {
	mk := func(name, host, policy string) *v1.Silo {
		s := &v1.Silo{}
		s.Name, s.Namespace, s.Status.Host, s.Spec.Availability.OnHostLoss = name, "d", host, policy
		return s
	}
	move, stay := DrainPlan("hv1", []*v1.Silo{mk("runner", "hv1", "Recreate"), mk("db", "hv1", ""), mk("web", "hv1", "Wait"), mk("other", "hv2", "Recreate")})
	if len(move) != 1 || move[0].Name != "runner" || len(stay) != 2 {
		t.Fatalf("move %v stay %v", move, stay)
	}
}
