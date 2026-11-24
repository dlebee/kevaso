package admconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pubKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + comment
}

func TestPickTheFlagThenTheEnvThenTheOnlyCluster(t *testing.T) {
	root := t.TempDir()
	t.Setenv(EnvCluster, "")
	if _, err := Pick(root, ""); err == nil || !strings.Contains(err.Error(), "kvoadm init") {
		t.Fatalf("no cluster: %v", err)
	}
	if err := New(root, "home").Save(); err != nil {
		t.Fatal(err)
	}
	if got, err := Pick(root, ""); err != nil || got != "home" {
		t.Fatalf("the only cluster: %q %v", got, err)
	}
	if err := New(root, "work").Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := Pick(root, ""); err == nil || !strings.Contains(err.Error(), "home, work") {
		t.Fatalf("two clusters, none named: %v", err)
	}
	t.Setenv(EnvCluster, "work")
	if got, _ := Pick(root, ""); got != "work" {
		t.Fatalf("env: %q", got)
	}
	if got, _ := Pick(root, "home"); got != "home" {
		t.Fatalf("the flag wins: %q", got)
	}
	_ = os.MkdirAll(filepath.Join(root, "clusters", "empty"), 0o700) // a folder without cluster.yaml
	if cs, _ := Clusters(root); !reflect.DeepEqual(cs, []string{"home", "work"}) {
		t.Fatalf("clusters: %v", cs)
	}
}

// The shared file holds nothing secret: the credential and the private key path go to local.yaml,
// and git sees only cluster.yaml.
func TestTwoFilesSharedAndLocal(t *testing.T) {
	root := t.TempDir()
	c := New(root, "home")
	c.Shared.Server = "https://cp:6443"
	c.Local.Admin, c.Local.SSHKey = "david", "/home/david/.ssh/id_ed25519"
	if err := c.WriteCredentials([]byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"), []byte("cert"), []byte("-----BEGIN EC PRIVATE KEY-----\nk\n-----END EC PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAdmin("david", pubKey(t, "david@laptop")); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	shared, _ := os.ReadFile(c.SharedPath())
	for _, secret := range []string{"admin.key", "PRIVATE KEY", "id_ed25519", "certificate"} {
		if strings.Contains(string(shared), secret) {
			t.Fatalf("cluster.yaml holds %q:\n%s", secret, shared)
		}
	}
	for p, want := range map[string]os.FileMode{c.Folder(): 0o700, c.SharedPath(): 0o644, c.LocalPath(): 0o600, c.File("admin.key"): 0o600, c.File("admin.crt"): 0o600} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v, want %v", p, st.Mode().Perm(), err, want)
		}
	}
	gi, _ := os.ReadFile(filepath.Join(c.Folder(), ".gitignore"))
	if !strings.Contains(string(gi), "*\n!cluster.yaml\n") {
		t.Fatalf(".gitignore:\n%s", gi)
	}
	got, err := Load(root, "home")
	if err != nil {
		t.Fatal(err)
	}
	if got.Server() != "https://cp:6443" || got.SSHKey() != "/home/david/.ssh/id_ed25519" || got.Local.Admin != "david" || !strings.Contains(string(got.CAPEM()), "ca") {
		t.Fatalf("loaded: %+v", got)
	}
	if ctx := got.Context(); ctx.Key != filepath.Join(root, "clusters", "home", "admin.key") {
		t.Fatalf("the key is the folder's: %q", ctx.Key)
	}
	// A teammate's clone: cluster.yaml alone.
	_ = os.Remove(got.LocalPath())
	clone, err := Load(root, "home")
	if err != nil || clone.SSHKey() != "" || len(clone.Shared.Admins) != 1 {
		t.Fatalf("a clone without local.yaml: %+v %v", clone, err)
	}
	if _, err := clone.Client(); err == nil || !strings.Contains(err.Error(), "no admin credential on this machine") {
		t.Fatalf("no credential here: %v", err)
	}
	if _, err := Load(root, "nope"); err == nil || !strings.Contains(err.Error(), "kvoadm init") {
		t.Fatalf("a missing cluster: %v", err)
	}
}

// A shared file with a secret in it, or a field that belongs in local.yaml, is refused on read
// and never written.
func TestSharedFileRefusesSecrets(t *testing.T) {
	root := t.TempDir()
	dir := Dir(root, "c")
	_ = os.MkdirAll(dir, 0o700)
	for name, text := range map[string]string{
		"a credential path": "cluster: c\nserver: https://x:6443\nkey: admin.key\n",
		"a private key":     "cluster: c\nca: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  x\n",
		"a recovery key":    "cluster: c\nserver: KVR1-AAAA\n",
		"a bad admin key":   "cluster: c\nadmins:\n  - name: eve\n    sshKeys: [\"not a key\"]\n",
	} {
		_ = os.WriteFile(filepath.Join(dir, SharedFile), []byte(text), 0o644)
		if _, err := Load(root, "c"); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	c := New(root, "d")
	c.Shared.Server = "-----BEGIN RSA PRIVATE KEY-----"
	if err := c.Save(); err == nil {
		t.Fatal("a secret written into cluster.yaml")
	}
	if err := c.SetAdmin("eve", "-----BEGIN OPENSSH PRIVATE KEY-----"); err == nil {
		t.Fatal("a private key as an admin's key")
	}
	if err := c.SetAdmin("two words", pubKey(t, "x")); err == nil {
		t.Fatal("an admin name with a space")
	}
}

// This machine's addresses come first, then the team's; each once.
func TestAddressesLocalThenShared(t *testing.T) {
	c := New(t.TempDir(), "home")
	_, _ = c.AddAddresses("h", false, "192.168.1.50")
	c.RecordHost("h", "root@100.64.0.9", "SHA256:x") // what host add used goes first in the team's list
	_, _ = c.AddAddresses("h", false, "192.168.1.50", "h.ts.net")
	_, _ = c.AddAddresses("h", true, "root@10.0.0.7", "h.ts.net")
	if got := c.Addresses("h"); !reflect.DeepEqual(got, []string{"root@10.0.0.7", "h.ts.net", "root@100.64.0.9", "192.168.1.50"}) {
		t.Fatalf("order: %v", got)
	}
	if c.HostKey("h") != "SHA256:x" || !c.HasHost("h") {
		t.Fatal("the pinned key is this machine's")
	}
	if r := c.RemoveAddresses("h", "h.ts.net", "not-there"); !reflect.DeepEqual(r, []string{"h.ts.net"}) {
		t.Fatalf("removed from both lists once: %v", r)
	}
	if n, ok := c.HostFor("100.64.0.9:22"); !ok || n != "h" {
		t.Fatalf("host for an address: %q %v", n, ok)
	}
	if _, err := c.AddAddresses("h", false, "bad address"); err == nil {
		t.Fatal("a bad address is refused")
	}
	c.ForgetHost("h")
	if c.HasHost("h") {
		t.Fatal("forgotten in both files")
	}
}

func TestAdmins(t *testing.T) {
	c := New(t.TempDir(), "home")
	k1, k2 := pubKey(t, "a"), pubKey(t, "b")
	_ = c.SetAdmin("david", k1)
	_ = c.SetAdmin("ana", k2)
	_ = c.SetAdmin("david", k1, k2) // replaces david's keys
	if len(c.Shared.Admins) != 2 || len(c.Shared.Admins[0].SSHKeys) != 2 {
		t.Fatalf("admins: %+v", c.Shared.Admins)
	}
	if !c.RemoveAdmin("ana") || c.RemoveAdmin("ana") {
		t.Fatal("remove reports whether there was one")
	}
}

func TestParseAddress(t *testing.T) {
	for in, want := range map[string]Target{
		"192.168.1.50":       {User: "root", Host: "192.168.1.50", Port: 22},
		"me@h.ts.net:2222":   {User: "me", Host: "h.ts.net", Port: 2222},
		"[fd00::5]:2200":     {User: "root", Host: "fd00::5", Port: 2200},
		"admin@[fd00::5]":    {User: "admin", Host: "fd00::5", Port: 22},
		"  10.0.0.1  ":       {User: "root", Host: "10.0.0.1", Port: 22},
		"ops@203.0.113.9:22": {User: "ops", Host: "203.0.113.9", Port: 22},
	} {
		got, err := ParseAddress(in, "root", 22)
		if err != nil || got != want {
			t.Fatalf("%q: %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "@h", "h:0", "h:x", "a b", "u@"} {
		if _, err := ParseAddress(bad, "root", 22); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if s := (Target{User: "root", Host: "fd00::5", Port: 22}).String(); s != "root@[fd00::5]:22" {
		t.Fatal(s)
	}
}

// Two kvoadm runs at once (host add of two workers) each keep the other's change.
func TestUpdatesAtOnceKeepEachOther(t *testing.T) {
	root := t.TempDir()
	if err := New(root, "c").Save(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	for i := range 12 {
		go func() {
			c, err := Load(root, "c") // each run read the file before the others wrote
			if err != nil {
				done <- err
				return
			}
			done <- c.Update(func(c *Config) error {
				c.RecordHost(fmt.Sprintf("w%d", i), fmt.Sprintf("root@10.0.0.%d", i), "SHA256:k")
				return nil
			})
		}()
	}
	for range 12 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	c, err := Load(root, "c")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Shared.Hosts) != 12 || len(c.Local.Hosts) != 12 {
		t.Fatalf("lost updates: %d shared, %d local", len(c.Shared.Hosts), len(c.Local.Hosts))
	}
	if _, err := os.Stat(filepath.Join(c.Folder(), ".lock")); !os.IsNotExist(err) {
		t.Fatal("the lock is left behind")
	}
}
