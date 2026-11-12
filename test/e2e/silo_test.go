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

// The example 01 silo, plus init steps that prove they ran inside the microVM.
const example01 = `
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: demo }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: hello, namespace: demo }
spec:
  runtime: cloud-hypervisor
  image: ubuntu-24.04
  resources: { cpu: 1, memory: 1Gi }
  disk: { size: 10Gi }
  init:
    steps:
      - name: proof
        run: echo "made inside $(hostname)" > /root/proof && cat /root/proof
      - name: python
        shell: python3
        run: |
          import platform; print("kernel", platform.release())
      - name: gateway
        run: ping -c1 -W2 10.64.0.1
`

// TestExample01RunsASiloOnCloudHypervisor is M3's "done when": one host with the control plane
// and a worker, `kvo apply` of example 01, and the silo boots on Cloud Hypervisor, runs its init
// steps inside the VM, and reports Ready.
func TestExample01RunsASiloOnCloudHypervisor(t *testing.T) {
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

	run := testbed.NewRunID()
	spec := testbed.Spec{Role: "hv", CPUs: 4, Memory: "6GiB", Disk: "60GiB", KVM: true}
	planned := testbed.Machine{Name: testbed.MachineName(run, spec.Role), Run: run, Role: spec.Role}
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING %s for debugging (limactl delete -f %s)", planned.Name, planned.Name)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := d.Delete(ctx, planned); err != nil {
			t.Errorf("teardown %s: %v", planned.Name, err)
		}
	})
	m, err := d.Create(ctx, run, spec)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	info, err := sshd.SSH(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Exec(ctx, m, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	pin := strings.Fields(out)[1]
	bin := filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}

	var stdout, stderr bytes.Buffer
	if code := kvoadm.Run(ctx, []string{"init", info.User + "@" + info.Host,
		"--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile, "--host-key", pin,
		"--kevasod", bin, "--name", "hv1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443",
		"--worker", "--loop-storage", "40G",
	}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("kvoadm init: %s\n%s", stdout.String(), stderr.String())
	}
	t.Logf("kvoadm init:\n%s", stdout.String())

	kvoRun := func(stdin string, args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := kvo.Run(ctx, args, strings.NewReader(stdin), &o, &e)
		return o.String(), e.String(), code
	}
	if o, e, code := kvoRun(example01, "apply", "-f", "-"); code != 0 {
		t.Fatalf("apply: %s %s", o, e)
	}

	// Wait for Ready (the runtime installs first: downloads, packages, the image).
	deadline := time.Now().Add(30 * time.Minute)
	var last string
	for {
		y, _, _ := kvoRun("", "get", "silo", "hello", "-n", "demo", "-o", "yaml")
		if y != last {
			t.Logf("silo status:\n%s", tailLines(y, 30))
			last = y
		}
		if strings.Contains(y, "reason: Running") && strings.Contains(y, "phase: Running") {
			for _, want := range []string{"name: proof", "name: python", "name: gateway", "state: Done", "address: 10.64.0."} {
				if !strings.Contains(y, want) {
					t.Fatalf("Ready, but missing %q:\n%s", want, y)
				}
			}
			break
		}
		if strings.Contains(y, "InitFailed") || strings.Contains(y, "phase: Failed") {
			journal, _ := d.Exec(ctx, m, "sudo", "journalctl", "-u", "kevasod", "-n", "60", "--no-pager")
			t.Fatalf("silo failed:\n%s\nkevasod:\n%s", y, journal)
		}
		if time.Now().After(deadline) {
			journal, _ := d.Exec(ctx, m, "sudo", "journalctl", "-u", "kevasod", "-n", "80", "--no-pager")
			hosts, _, _ := kvoRun("", "get", "hosts", "-o", "yaml")
			t.Fatalf("silo never Ready:\n%s\nhosts:\n%s\nkevasod:\n%s", y, hosts, journal)
		}
		time.Sleep(10 * time.Second)
	}

	// The VMM really runs locked down (research E010): its own user, no capabilities,
	// no-new-privileges, a syscall filter.
	st, err := d.Exec(ctx, m, "sudo", "sh", "-c",
		`p=$(pgrep -f /opt/kevaso/cloud-hypervisor/cloud-hypervisor | head -1); ps -o user:20= -p $p; grep -E "^(CapEff|NoNewPrivs|Seccomp):" /proc/$p/status`)
	if err != nil {
		t.Fatalf("inspect VMM: %v %s", err, st)
	}
	t.Logf("VMM:\n%s", st)
	for _, want := range []string{"kevaso-vmm", "CapEff:\t0000000000000000", "NoNewPrivs:\t1", "Seccomp:\t2"} {
		if !strings.Contains(st, want) {
			t.Fatalf("VMM not locked down: missing %q in\n%s", want, st)
		}
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
