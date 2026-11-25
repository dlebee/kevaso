//go:build metal

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"kevaso.com/core/internal/admconfig"
	"kevaso.com/core/internal/sshboot"
)

// TestLabKvoadmClusterFolder is kvoadm's per-cluster folder on a worktree lab (testbed/lab), as
// lab-up's kvoadm init and host add left it: the shared cluster.yaml and the local local.yaml,
// hosts reached by name through their address list (a dead address and another machine's first),
// admins' keys put on every host and taken off again, a teammate's clone without credentials, a
// system node installed and uninstalled through the list, and a worker reset by name and removed.
//
// Source testbed/lab/.labs/NAME/env.sh first (a cluster lab, not a pair lab). Without LAB_NAME
// the test skips. It changes the lab (w2 is reset and removed): run it on a lab made for it.
func TestLabKvoadmClusterFolder(t *testing.T) {
	lab := os.Getenv("LAB_NAME")
	if lab == "" || os.Getenv("KEVASO_METAL2_HOST") != "" {
		t.Skip("LAB_NAME is unset or this is a pair lab: source a cluster lab's testbed/lab/.labs/NAME/env.sh")
	}
	labDir := os.Getenv("LAB_DIR")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	run := func(args ...string) string { t.Helper(); return labKvoadm(t, ctx, labDir, args...) }
	root := filepath.Join(labDir, ".kevaso")
	t.Setenv(admconfig.EnvHome, root)
	t.Setenv(admconfig.EnvCluster, "")

	// 1. The folder: two files, the shared one secret-free, git told to keep the rest out.
	kc, err := admconfig.Load(root, lab)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := os.ReadFile(kc.SharedPath())
	for _, s := range []string{"PRIVATE KEY", "admin.key", "sshKey:", "hostKey:", "certificate:"} {
		if strings.Contains(string(shared), s) {
			t.Fatalf("cluster.yaml holds %q:\n%s", s, shared)
		}
	}
	for _, f := range []string{".gitignore", "local.yaml", "admin.crt", "admin.key", "signing.key"} {
		if _, err := os.Stat(filepath.Join(kc.Folder(), f)); err != nil {
			t.Fatalf("the cluster folder lacks %s: %v", f, err)
		}
	}
	for _, h := range []string{"sys", "w1", "w2"} {
		if len(kc.Shared.Hosts[h].Addresses) == 0 || kc.HostKey(h) == "" {
			t.Fatalf("host %s: shared addresses %v, pinned key %q", h, kc.Shared.Hosts[h].Addresses, kc.HostKey(h))
		}
	}
	if len(kc.Shared.Admins) != 1 || kc.Local.Admin == "" || kc.Shared.Admins[0].Name != kc.Local.Admin {
		t.Fatalf("init made you the first admin: %+v, local %q", kc.Shared.Admins, kc.Local.Admin)
	}
	t.Logf("step 1: %s holds %d hosts and admin %s; local.yaml has the credential", kc.SharedPath(), len(kc.Shared.Hosts), kc.Local.Admin)

	// 2. The admins' keys are on every host already (init and host add put them there).
	if out := run("admins", "sync", "--dry-run"); strings.Count(out, "up to date") != 3 {
		t.Fatalf("admins sync --dry-run after lab-up:\n%s", out)
	}

	// 3. w1 by name, with a dead address and w2's address (another machine) tried first.
	w1 := kc.Shared.Hosts["w1"].Addresses[0]
	w2 := kc.Shared.Hosts["w2"].Addresses[0]
	t1, _ := admconfig.ParseAddress(w1, "root", 22)
	dead := t1.User + "@" + t1.Host + ":1"
	run("host", "ssh", "w1", "add", dead, w2, "--local")
	if out := run("host", "ssh", "w1"); !strings.HasPrefix(out, "1.") || !strings.Contains(out, "this machine (local.yaml)") {
		t.Fatalf("w1's list:\n%s", out)
	}
	out := run("host", "kept", "w1")
	if !strings.Contains(out, "reached at "+t1.String()) || !strings.Contains(out, "expected "+kc.HostKey("w1")) {
		t.Fatalf("w1 through its list (the dead address and w2 skipped):\n%s", out)
	}
	t.Logf("step 3: w1 reached at its third address; the first refused, the second is w2 (its host key isn't w1's)")
	if out := run("host", "reconnect", "w1"); !strings.Contains(out, "reports to") {
		t.Fatalf("reconnect by name:\n%s", out)
	}
	run("host", "ssh", "w1", "remove", dead, w2)

	// 4. A new admin: in the file, synced to every host, able to log in; removed and locked out.
	anaKey, anaPub := labNewKey(t)
	run("admins", "add", "ana", anaPub)
	if out := run("admins", "sync"); strings.Count(out, "updated") != 3 {
		t.Fatalf("admins sync:\n%s", out)
	}
	if got, err := labSSHAs(ctx, t1, kc.HostKey("w1"), anaKey, "id -un"); err != nil || strings.TrimSpace(got) != t1.User {
		t.Fatalf("ana on w1: %q %v", got, err)
	}
	run("admins", "remove", "ana")
	run("admins", "sync")
	if _, err := labSSHAs(ctx, t1, kc.HostKey("w1"), anaKey, "true"); err == nil {
		t.Fatal("ana still gets in after admins remove and sync")
	}
	t.Logf("step 4: admin ana added, synced to 3 hosts, logged in to w1, removed and refused")

	// 5. A teammate's clone: cluster.yaml alone. kvoadm knows the hosts but has no credential.
	clone := t.TempDir()
	cdir := admconfig.Dir(clone, lab)
	_ = os.MkdirAll(cdir, 0o700)
	_ = os.WriteFile(filepath.Join(cdir, admconfig.SharedFile), shared, 0o644)
	t.Setenv(admconfig.EnvHome, clone)
	o, code := labKvoadmCode(ctx, labDir, "host", "list")
	t.Setenv(admconfig.EnvHome, root)
	if code == 0 || !strings.Contains(o, "no admin credential on this machine") {
		t.Fatalf("a clone without local.yaml: exit %d\n%s", code, o)
	}

	// 6. users, through the folder.
	run("users", "invite", "kvcfgbob", "--cluster", lab)
	if out := run("users", "list"); !strings.Contains(out, "kvcfgbob") {
		t.Fatalf("users list:\n%s", out)
	}

	// 7. A system node: sys's store to etcd (sys by name), then w1 gets the control plane through
	// its list, and its API is added to cluster.yaml; then uninstalled.
	run("store", "migrate", "sys")
	run("host", "install", "w1", "control-plane")
	kc2, _ := admconfig.Load(root, lab)
	if !strings.Contains(kc2.Server(), ",") {
		t.Fatalf("w1's API not added to cluster.yaml's server list: %q", kc2.Server())
	}
	run("host", "uninstall", "w1", "control-plane")
	t.Logf("step 7: w1 a system node and back; cluster.yaml server list %s", kc2.Server())

	// 8. w2 reset by name, then removed: it leaves cluster.yaml.
	run("reset", "w2", "--yes", "--force")
	run("host", "remove", "w2")
	kc3, _ := admconfig.Load(root, lab)
	if kc3.HasHost("w2") {
		t.Fatal("w2 still in the cluster folder after host remove")
	}
	t.Logf("step 8: w2 reset by name and removed from the cluster and the folder")
}

func labNewKey(t *testing.T) (string, string) {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(t.TempDir(), "ana")
	_ = os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	s, _ := ssh.NewSignerFromKey(k)
	_ = os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(s.PublicKey()), 0o644)
	return p, p + ".pub"
}

// labSSHAs logs in to a target with a key and the pinned host key and runs one command.
func labSSHAs(ctx context.Context, tg admconfig.Target, hostKey, keyPath, cmd string) (string, error) {
	b, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return "", err
	}
	conn, err := sshboot.Connect(ctx, sshboot.Target{Addr: strings.TrimPrefix(tg.String(), tg.User+"@"), User: tg.User},
		sshboot.HostKeyPolicy{Pin: hostKey}, sshboot.Auth{Signer: signer})
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	out, err := conn.Run(ctx, cmd, nil)
	return string(out), err
}
