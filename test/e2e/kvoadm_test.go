//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// TestKvoadmInitMakesAReadyHost is M2's "done when": a fresh machine, `kvoadm init` over SSH,
// and `kvo get hosts` over TLS shows it Ready.
//
//  1. create machine   2. kvoadm init   3. kvo get hosts → Ready   4. tear down
func TestKvoadmInitMakesAReadyHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	d, arch := driver(t)
	sshd, ok := d.(testbed.SSHAccess)
	if !ok {
		t.Skip("this testbed driver can't hand out SSH access (CI's local driver: TODO, run sshd on the runner)")
	}
	// kvoadm keeps keys and the kvo config under $HOME/.kevaso: use a throwaway home, but keep Lima
	// on its real folder (its sockets need short paths, and its image cache lives there).
	if os.Getenv("LIMA_HOME") == "" {
		real, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("LIMA_HOME", filepath.Join(real, ".lima"))
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KVO_CONFIG", filepath.Join(home, ".kevaso", "config.yaml"))

	run := testbed.NewRunID()
	spec := testbed.Spec{Role: "cp", CPUs: 2, Memory: "2GiB", Disk: "10GiB"}
	planned := testbed.Machine{Name: testbed.MachineName(run, spec.Role), Run: run, Role: spec.Role}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := d.Delete(ctx, planned); err != nil {
			t.Errorf("teardown %s: %v", planned.Name, err)
		}
	})

	// 1. create
	m, err := d.Create(ctx, run, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := sshd.SSH(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	// The host key to pin, read through the testbed's own channel (as a provider console would show it).
	out, err := d.Exec(ctx, m, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatalf("read host key: %v %s", err, out)
	}
	fields := strings.Fields(out)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "SHA256:") {
		t.Fatalf("host key fingerprint from %q", out)
	}
	pin := fields[1]

	// A kevasod for the machine's CPU.
	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kevasod: %v\n%s", err, b)
	}

	// 2. kvoadm init (a key login with sudo, as on most cloud images; the host key pinned).
	var stdout, stderr bytes.Buffer
	code := kvoadm.Run(ctx, []string{"init", info.User + "@" + info.Host,
		"--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile, "--host-key", pin,
		"--kevasod", bin, "--name", "cp-1", "--cluster", "e2e",
		// Lima forwards the guest's 6443 to the Mac's loopback.
		"--api-server", "https://127.0.0.1:6443",
	}, strings.NewReader(""), &stdout, &stderr)
	t.Logf("kvoadm init:\n%s", stdout.String())
	if code != 0 {
		t.Fatalf("kvoadm init exit %d: %s", code, stderr.String())
	}

	// 3. kvo, from the context kvoadm wrote, over TLS.
	var kout, kerr bytes.Buffer
	if code := kvo.Run(ctx, []string{"get", "hosts", "-o", "yaml"}, nil, &kout, &kerr); code != 0 {
		t.Fatalf("kvo get hosts: exit %d: %s", code, kerr.String())
	}
	y := kout.String()
	t.Logf("kvo get hosts -o yaml:\n%s", y)
	for _, want := range []string{"name: cp-1", "type: Ready", "status: \"True\"", "controlPlane: {}"} {
		if !strings.Contains(y, want) {
			t.Fatalf("host isn't Ready: missing %q", want)
		}
	}

	// It runs as a systemd service.
	if out, err := d.Exec(ctx, m, "sudo", "systemctl", "is-active", "kevasod"); err != nil || strings.TrimSpace(out) != "active" {
		t.Fatalf("kevasod.service: %q %v", out, err)
	}
}
