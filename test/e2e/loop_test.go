//go:build e2e

// Package e2e runs the test loop on real machines:
//
//  1. create machine(s)   2. add them with kvoadm   3. test   4. tear down
//
// M0 has only steps 1, 3 and 4, with "the machine can run microVMs" as the test. Later milestones add
// kvoadm (step 2) and grow step 3; the harness stays the same.
//
// Driver selection (KEVASO_TESTBED): "lima" (default on macOS) creates a Lima VM; "local" uses this
// machine (CI on GitHub's ubuntu-latest runner).
package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/testbed"
	"kevaso.com/core/testbed/lima"
	"kevaso.com/core/testbed/local"
)

func driver(t *testing.T) (testbed.Driver, string) {
	name := os.Getenv("KEVASO_TESTBED")
	if name == "" {
		name = "lima"
		if runtime.GOOS == "linux" {
			name = "local"
		}
	}
	switch name {
	case "lima":
		return lima.New(), "arm64"
	case "local":
		return local.Driver{}, runtime.GOARCH
	}
	t.Fatalf("unknown KEVASO_TESTBED %q", name)
	return nil, ""
}

func TestLoopMachineRunsMicroVMs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	d, arch := driver(t)
	run := testbed.NewRunID()
	t.Logf("run %s", run)

	// Sweep leftovers of earlier crashed runs first (older than 2h, testbed names only).
	if all, err := d.List(ctx); err == nil {
		for _, m := range testbed.Leftovers(all, run, time.Now(), 2*time.Hour) {
			t.Logf("sweeping leftover %s", m.Name)
			_ = d.Delete(ctx, m)
		}
	}

	// 4. tear down, always, even when the test fails or create only got halfway: delete by the name
	// the machine gets, not by what Create returned.
	spec := testbed.Spec{Role: "w1", CPUs: 2, Memory: "2GiB", Disk: "10GiB", KVM: true}
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

	// 3. test: the machine exposes a usable /dev/kvm
	bin := filepath.Join(t.TempDir(), "kvmcheck")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "kevaso.com/core/cmd/kvmcheck")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kvmcheck: %v\n%s", err, out)
	}
	remote := "/tmp/kvt-kvmcheck-" + string(run)
	if err := d.CopyTo(ctx, m, bin, remote); err != nil {
		t.Fatalf("copy: %v", err)
	}
	out, err := d.Exec(ctx, m, "sh", "-c", "chmod +x "+remote+" && "+remote+"; rc=$?; rm -f "+remote+"; exit $rc")
	t.Logf("kvmcheck on %s:\n%s", m.Name, out)
	if err != nil || !strings.Contains(out, "PASS") {
		t.Fatalf("machine %s can't run microVMs: %v", m.Name, err)
	}
}
