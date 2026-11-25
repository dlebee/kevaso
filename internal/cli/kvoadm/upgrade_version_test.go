package kvoadm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpgradeRefusesABinaryWithNoVersion(t *testing.T) {
	for _, stamped := range []string{"", "v0.0.0-dev"} {
		if _, err := UpgradeTarget(stamped, "v0.3.1"); err == nil || !strings.Contains(err.Error(), "no version") {
			t.Fatalf("stamped %q: %v", stamped, err)
		}
		if _, err := UpgradeTarget(stamped, ""); err == nil || !strings.Contains(err.Error(), "no version") {
			t.Fatalf("stamped %q with no flag: %v", stamped, err)
		}
	}
	got, err := UpgradeTarget("v0.3.1", "v0.3.1")
	if err != nil || got != "v0.3.1" {
		t.Fatalf("matching flag: %s %v", got, err)
	}
	got, err = UpgradeTarget("v0.3.1", "")
	if err != nil || got != "v0.3.1" {
		t.Fatalf("no flag: %s %v", got, err)
	}
	if _, err := UpgradeTarget("v0.3.1", "v9.9.9"); err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "v0.3.1") {
		t.Fatalf("different flag: %v", err)
	}
}

// tinyBuild compiles a small program for goos/arch with the version kvoadm reads stamped in.
func tinyBuild(t *testing.T, goos, arch, version string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module tiny\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "kevasod-"+goos+"-"+arch)
	cmd := exec.Command("go", "build", "-o", out, "-ldflags", "-X "+versionVar+"="+version, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+arch, "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s/%s: %v\n%s", goos, arch, err, b)
	}
	return out
}

// A cluster with Linux workers and a Mac takes a build for each; a Linux kevasod is never sent to
// a Mac (found reading kvoadm upgrade: one --kevasod went to every host, whatever it ran).
func TestUpgradeTakesOneBuildPerOSAndCPU(t *testing.T) {
	if testing.Short() {
		t.Skip("builds programs")
	}
	linux := tinyBuild(t, "linux", "amd64", "v0.1.0-rc.7")
	mac := tinyBuild(t, "darwin", "arm64", "v0.1.0-rc.7")
	builds, target, err := upgradeBuilds([]string{linux, mac}, "")
	if err != nil || target != "v0.1.0-rc.7" {
		t.Fatalf("two builds: %v %v", target, err)
	}
	if builds["linux/x86_64"] != linux || builds["darwin/arm64"] != mac {
		t.Fatalf("builds by platform: %v", builds)
	}
	hosts := map[string]string{"cp1": "linux/x86_64", "w1": "linux/x86_64", "mac1": "darwin/arm64", "pi": "linux/aarch64"}
	if got := MissingBuilds(hosts, builds); len(got) != 1 || got[0] != "pi (linux/aarch64)" {
		t.Fatalf("missing: %v", got)
	}
	linuxOnly, _, _ := upgradeBuilds([]string{linux}, "")
	if got := MissingBuilds(hosts, linuxOnly); strings.Join(got, ",") != "mac1 (darwin/arm64),pi (linux/aarch64)" {
		t.Fatalf("a Linux build only: %v", got)
	}
	if _, _, err := upgradeBuilds([]string{linux, linux}, ""); err == nil || !strings.Contains(err.Error(), "both for linux/x86_64") {
		t.Fatalf("two builds for one platform: %v", err)
	}
	other := tinyBuild(t, "darwin", "arm64", "v0.1.0-rc.8")
	if _, _, err := upgradeBuilds([]string{linux, other}, ""); err == nil || !strings.Contains(err.Error(), "different versions") {
		t.Fatalf("mixed versions: %v", err)
	}
	if _, _, err := upgradeBuilds(nil, ""); err == nil {
		t.Fatal("no build")
	}
}

func TestUnamePlatform(t *testing.T) {
	for in, want := range map[string]string{"Linux x86_64\n": "linux/x86_64", "Darwin arm64": "darwin/arm64", "Linux aarch64": "linux/aarch64"} {
		if got, err := UnamePlatform(in); err != nil || got != want {
			t.Fatalf("%q: %s %v", in, got, err)
		}
	}
	if _, err := UnamePlatform("Linux"); err == nil {
		t.Fatal("one field")
	}
}
