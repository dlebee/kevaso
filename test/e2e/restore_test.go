//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/kms"
	"kevaso.com/core/testbed"
)

// TestBackupAndRestore: the control plane's machine is lost. kvoadm init made a cluster and printed
// the recovery key, kvoadm host add gave it a worker, kvoadm backup took a backup; the machine is
// deleted; kvoadm init --restore on a fresh machine (another address) brings the cluster back, its
// secrets opening with the master key rebuilt from the recovery key, and reconnects the worker to
// it, mesh included.
func TestBackupAndRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	d, arch := driver(t)
	sshd, ok := d.(testbed.SSHAccess)
	if !ok {
		t.Skip("needs a driver with SSH access (Lima)")
	}
	if os.Getenv("LIMA_HOME") == "" {
		real, _ := os.UserHomeDir()
		t.Setenv("LIMA_HOME", filepath.Join(real, ".lima"))
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KVO_CONFIG", filepath.Join(home, ".kevaso", "config.yaml"))
	t.Setenv("KVO_SERVER", "")

	run := testbed.NewRunID()
	created := map[string]testbed.Machine{}
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" && t.Failed() {
			t.Logf("KEEPING the run's machines (limactl list | grep %s)", run)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, m := range created {
			_ = d.Delete(ctx, m)
		}
	})
	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	kvoadmRun := func(stdin string, args ...string) string {
		t.Helper()
		var o, e bytes.Buffer
		if code := kvoadm.Run(ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
			t.Fatalf("kvoadm %v: exit %d\n%s%s", args, code, o.String(), e.String())
		}
		return o.String()
	}
	kvoMust := func(stdin string, args ...string) string {
		t.Helper()
		var o, e bytes.Buffer
		if code := kvo.Run(ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
			t.Fatalf("kvo %v: exit %d\n%s%s", args, code, o.String(), e.String())
		}
		return o.String()
	}
	machine := func(role string) (testbed.Machine, []string, string) {
		t.Helper()
		m, err := d.Create(ctx, run, testbed.Spec{Role: role, CPUs: 2, Memory: "2GiB", Disk: "10GiB", Shared: true})
		if err != nil {
			t.Fatalf("create %s: %v", role, err)
		}
		created[role] = m
		info, err := sshd.SSH(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		hk, _ := d.Exec(ctx, m, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
		ip, _ := d.Exec(ctx, m, "sh", "-c", `ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1`)
		ip = strings.TrimSpace(ip)
		return m, []string{info.User + "@" + info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
			"--host-key", strings.Fields(hk)[1]}, ip
	}

	// 1. A cluster, with a secret.
	a, target, ipA := machine("cpa")
	initOut := kvoadmRun("", append(append([]string{"init"}, target...), "--kevasod", bin, "--name", "cp-1", "--cluster", "e2e",
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", ipA)...)
	rk := regexp.MustCompile(`KVR1-[A-Z0-9-]+`).FindString(initOut)
	if rk == "" {
		t.Fatalf("no recovery key in:\n%s", initOut)
	}
	_, targetW, ipW := machine("w1")
	t.Log(kvoadmRun("", append(append([]string{"host", "add"}, targetW...), "--kevasod", bin, "--name", "w1", "--install", "worker",
		"--runtime", "none", "--internal-ip", ipW, "--server", "https://"+ipA+":6443")...))
	const password = "s3cret-db-password-0123"
	kvoMust("apiVersion: kevaso/v1\nkind: Namespace\nmetadata: { name: payments }\n", "apply", "-f", "-")
	kvoMust(password, "create", "secret", "db", "-n", "payments", "--from-file", "-")

	// 2. A backup, to a file here.
	file := filepath.Join(t.TempDir(), "e2e.kvb")
	t.Log(kvoadmRun("", append([]string{"backup"}, append(target, "--output", file)...)...))
	blob, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte(password)) || bytes.Contains(blob, []byte("PRIVATE KEY")) {
		t.Fatal("the backup file is readable without the recovery key")
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup file mode %v", fi.Mode().Perm())
	}

	// 3. The machine is lost.
	if err := d.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	delete(created, "cpa")

	// 4. A fresh machine; the wrong key is refused before anything changes, the right one restores.
	_, targetB, ipB := machine("cpb")
	var o, e bytes.Buffer
	if code := kvoadm.Run(ctx, append(append([]string{"init"}, targetB...), "--kevasod", bin, "--restore", file,
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", ipB),
		strings.NewReader(kms.NewRecoveryKey().String()+"\n"), &o, &e); code == 0 {
		t.Fatal("restored with a wrong recovery key")
	}
	t.Logf("wrong key: %s", strings.TrimSpace(e.String()))
	restoreOut := kvoadmRun(rk+"\n", append(append([]string{"init"}, targetB...), "--kevasod", bin, "--restore", file,
		"--api-server", "https://127.0.0.1:6443", "--internal-ip", ipB)...)
	t.Logf("kvoadm init --restore:\n%s", restoreOut)
	if strings.Contains(restoreOut, "KVR1-") {
		t.Error("restore printed a recovery key")
	}

	// 5. The cluster is back: the secret opens, and the host has its new address.
	if got := kvoMust("", "get", "secret", "db", "-n", "payments", "--reveal"); !strings.Contains(got, password) {
		t.Fatalf("secret after restore: %q", got)
	}
	t.Log("the secret opens on the restored control plane")
	deadline := time.Now().Add(2 * time.Minute)
	for {
		hosts := kvoMust("", "get", "host", "cp-1", "-o", "yaml")
		if strings.Contains(hosts, "address: "+ipB) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host cp-1 still at its old address:\n%s", hosts)
		}
		time.Sleep(3 * time.Second)
	}
	if ipA == ipB {
		t.Logf("host cp-1 at %s (both machines got the same address on this testbed; the move itself is covered by TestHostFollowsANewAddress)", ipB)
	} else {
		t.Logf("host cp-1 moved %s → %s", ipA, ipB)
	}

	// 6. The worker was reconnected by the restore, and the mesh works again: it reaches the new
	// control plane over WireGuard.
	if !strings.Contains(restoreOut, "worker w1 reconnected") {
		t.Fatalf("the restore didn't reconnect w1:\n%s", restoreOut)
	}
	var cpMesh string
	for deadline := time.Now().Add(3 * time.Minute); ; {
		hosts := parseHosts(t, []byte(kvoMust("", "get", "hosts", "-o", "json")))
		if cp := hosts["cp-1"]; cp != nil && cp.Status.Network.MeshIP != "" && cp.Status.Network.PublicKey != "" {
			cpMesh = cp.Status.Network.MeshIP
			out, err := d.Exec(ctx, created["w1"], "ping", "-c1", "-W2", cpMesh)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				wg, _ := d.Exec(ctx, created["w1"], "sudo", "wg", "show")
				t.Fatalf("w1 can't reach cp-1 at %s over the mesh: %v %s\n%s", cpMesh, err, out, wg)
			}
		} else if time.Now().After(deadline) {
			t.Fatal("cp-1 never published its mesh identity")
		}
		time.Sleep(3 * time.Second)
	}
	t.Logf("w1 reaches the restored cp-1 over the mesh (%s)", cpMesh)
}
