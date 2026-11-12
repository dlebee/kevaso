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
