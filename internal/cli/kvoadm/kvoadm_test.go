package kvoadm

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	v1 "kevaso.com/core/api/v1"
)

func TestParseInit(t *testing.T) {
	o, err := parseInit([]string{"ubuntu@203.0.113.10", "--kevasod", "/k", "--ssh-port", "2222", "--name", "cp-1", "--ssh-key", "/key"})
	if err != nil {
		t.Fatal(err)
	}
	if o.User != "ubuntu" || o.Address != "203.0.113.10" || o.SSHPort != 2222 || o.Name != "cp-1" || o.Kevasod != "/k" {
		t.Fatalf("parsed %+v", o)
	}
	o, _ = parseInit([]string{"203.0.113.10", "--kevasod", "/k", "--password"})
	if o.User != "root" || o.Name != "203-0-113-10" {
		t.Fatalf("defaults: %+v", o)
	}
	for _, bad := range [][]string{{}, {"a", "b", "--kevasod", "/k"}, {"a"}, {"a", "--kevasod", "/k", "--bogus"}, {"a", "--ssh-port", "x", "--kevasod", "/k"},
		{"a", "--kevasod", "/k"}, // how to log in: a key, or --password, said explicitly
		{"a", "--kevasod", "/k", "--ssh-key", "/key", "--password"}} {
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
	u := Unit(InitOptions{Name: "cp-1", Address: "203.0.113.10", ExternalIP: "203.0.113.10", Cluster: "home"})
	for _, want := range []string{
		"ExecStart=/usr/local/bin/kevasod control-plane --name cp-1 --external-ip 203.0.113.10 --cluster home",
		"Restart=always", "RuntimeDirectory=kevaso", "StateDirectoryMode=0700", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q", want)
		}
	}
}

func TestParseHostAdd(t *testing.T) {
	o, err := parseHostAdd([]string{"root@198.51.100.30", "--name", "worker-1", "--install", "worker", "--label", "gpu=no",
		"--region", "ca-central", "--zone", "tor", "--kevasod", "/k", "--internal-ip", "10.0.0.5", "--server", "https://10.0.0.1:6443", "--ssh-key", "/key"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Name != "worker-1" || o.Address != "198.51.100.30" || o.InternalIP != "10.0.0.5" || o.ExternalIP != "" || o.Region != "ca-central" || o.Zone != "tor" ||
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

// A host with a worker gets a fence of its own: the same runtimes, and nothing tying it to
// kevasod.service (it must keep running when kevasod stops or dies).
func TestFenceUnit(t *testing.T) {
	u := FenceUnit([]string{"docker", "podman"})
	if def := FenceUnit(nil); !strings.Contains(def, "--runtime cloud-hypervisor\n") {
		t.Fatalf("default runtimes:\n%s", def)
	}
	if !strings.Contains(u, "ExecStart=/usr/local/bin/kevasod fence-watch --fence-after 30s --runtime docker --runtime podman\n") ||
		!strings.Contains(u, "Restart=always") {
		t.Fatalf("fence unit:\n%s", u)
	}
	for _, tie := range []string{"PartOf", "BindsTo", "Requires", "kevasod.service"} {
		if strings.Contains(u, tie) {
			t.Errorf("fence unit is tied to kevasod (%s):\n%s", tie, u)
		}
	}
}

// init --store etcd starts the first system node on the embedded etcd member with a peer listener,
// so more system nodes can join without kvoadm store migrate.
func TestInitWithEtcdStore(t *testing.T) {
	o, err := parseInit([]string{"root@203.0.113.10", "--kevasod", "/k", "--ssh-key", "/key", "--name", "cp-1", "--store", "etcd"})
	if err != nil {
		t.Fatal(err)
	}
	if u := Unit(o); !strings.Contains(u, "--store etcd --etcd-peer-listen 203.0.113.10:2380") {
		t.Fatalf("unit:\n%s", u)
	}
	if o, _ := parseInit([]string{"root@a", "--kevasod", "/k", "--ssh-key", "/key"}); strings.Contains(Unit(o), "--store") {
		t.Fatal("SQLite is still the default")
	}
	if _, err := parseInit([]string{"root@a", "--kevasod", "/k", "--ssh-key", "/key", "--store", "mysql"}); err == nil {
		t.Fatal("--store mysql accepted")
	}
}

func TestUnitAdvertisesAnotherAddress(t *testing.T) {
	u := Unit(InitOptions{Name: "cp-1", Address: "127.0.0.1", InternalIP: "192.168.105.2", Cluster: "c"})
	if !strings.Contains(u, "--internal-ip 192.168.105.2 --cluster c --extra-name 127.0.0.1") {
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

func TestAssess(t *testing.T) {
	good := map[string]string{"os": "Ubuntu 24.04.1 LTS", "arch": "x86_64", "uid": "0", "systemd": "yes", "openssl": "yes", "apt": "yes",
		"kvm": "yes", "cpus": "4", "memory_mib": "8000", "disk_free_gib": "70", "password_login": "no", "kevasod": "absent", "port_6443": "free"}
	for _, r := range Assess(good) {
		if r.Level != "ok" {
			t.Errorf("a good machine: %+v", r)
		}
	}
	bad := map[string]string{}
	for k, v := range good {
		bad[k] = v
	}
	bad["arch"], bad["systemd"], bad["kvm"], bad["password_login"], bad["port_6443"] = "riscv64", "no", "no", "yes", "taken"
	levels := map[string]string{}
	for _, r := range Assess(bad) {
		levels[r.What] = r.Level
	}
	for what, want := range map[string]string{"CPU": "fail", "systemd": "fail", "KVM": "warn", "SSH password login": "warn", "port 6443": "fail"} {
		if levels[what] != want {
			t.Errorf("%s: %s, want %s", what, levels[what], want)
		}
	}
}

func TestWithWorker(t *testing.T) {
	cp := Unit(InitOptions{Name: "hv1", Address: "203.0.113.10", ExternalIP: "203.0.113.10", Cluster: "home"})
	got, err := WithWorker(cp, InitOptions{Runtimes: []string{"docker", "cloud-hypervisor"}, LoopStorage: "40G"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "ExecStart=/usr/local/bin/kevasod control-plane --name hv1 --external-ip 203.0.113.10 --cluster home --worker --runtime docker --runtime cloud-hypervisor --loop-storage /var/lib/kevaso-storage.img --loop-size 40G\n") {
		t.Fatalf("unit:\n%s", got)
	}
	// Again, with other runtimes: the worker flags are replaced, not added to.
	again, _ := WithWorker(got, InitOptions{Runtimes: []string{"podman"}})
	if strings.Count(again, "--worker") != 1 || strings.Contains(again, "docker") || strings.Contains(again, "loop") || !strings.Contains(again, "--runtime podman") {
		t.Fatalf("re-run:\n%s", again)
	}
	if _, err := WithWorker("[Service]\nExecStart=/usr/local/bin/kevasod worker --name x\n", InitOptions{}); err == nil {
		t.Fatal("rewrote a worker-only unit")
	}
	if Unit(InitOptions{Name: "a", Address: "b", Cluster: "c", Worker: true}) != func() string {
		u, _ := WithWorker(Unit(InitOptions{Name: "a", Address: "b", Cluster: "c"}), InitOptions{})
		return u
	}() {
		t.Error("init --worker and init + enable-worker should give the same unit")
	}
}

func TestLoadKeyWithPassphrase(t *testing.T) {
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(sk, "kevaso admin", []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err = loadKey("k", pem.EncodeToMemory(blk), strings.NewReader(""), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ssh-add") {
		t.Fatalf("a passphrase key without an agent or a terminal: %v", err)
	}
	plain, _ := ssh.MarshalPrivateKey(sk, "")
	if s, err := loadKey("k", pem.EncodeToMemory(plain), strings.NewReader(""), io.Discard); err != nil || s == nil {
		t.Fatalf("plain key: %v", err)
	}
}

// Every host that runs silos gets the fence, a control plane with a worker included (whether it
// acts is the agent's fence.Applies); a host without a worker gets none.
func TestUnitsFor(t *testing.T) {
	names := func(us []UnitFile) string {
		var out []string
		for _, u := range us {
			out = append(out, u.Name)
		}
		return strings.Join(out, ",")
	}
	init1, _ := parseInit([]string{"root@a", "--kevasod", "/k", "--ssh-key", "/key", "--worker", "--runtime", "docker"})
	for _, c := range []struct {
		name string
		us   []UnitFile
		want string
	}{
		{"control plane only", UnitsFor(Unit(InitOptions{Name: "cp"}), false, nil), "kevasod.service"},
		{"init --worker", UnitsFor(Unit(init1), init1.Worker, init1.Runtimes), "kevasod.service," + FenceUnitName},
		{"worker only", UnitsFor("x", true, []string{"docker"}), "kevasod.service," + FenceUnitName},
	} {
		if got := names(c.us); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if us := UnitsFor(Unit(init1), init1.Worker, init1.Runtimes); !strings.Contains(us[1].Text, "fence-watch --fence-after 30s --runtime docker\n") {
		t.Fatalf("fence of init --worker:\n%s", us[1].Text)
	}
}

func TestEditAddresses(t *testing.T) {
	got, err := EditAddresses(nil, "add", []string{"203.0.113.21/30", "203.0.113.9/32", "198.51.100.7"})
	if err != nil || strings.Join(got, " ") != "203.0.113.20/30 203.0.113.9 198.51.100.7" {
		t.Fatalf("add: %v %v", got, err)
	}
	if again, _ := EditAddresses(got, "add", []string{"203.0.113.20/30"}); len(again) != 3 {
		t.Fatalf("adding twice: %v", again)
	}
	got, err = EditAddresses(got, "remove", []string{"203.0.113.9"})
	if err != nil || strings.Join(got, " ") != "203.0.113.20/30 198.51.100.7" {
		t.Fatalf("remove: %v %v", got, err)
	}
	if _, err := EditAddresses(got, "remove", []string{"192.0.2.1"}); err == nil {
		t.Fatal("removing one it doesn't have")
	}
	if _, err := EditAddresses(got, "add", []string{"2001:db8::/64"}); err == nil {
		t.Fatal("IPv6")
	}
}
