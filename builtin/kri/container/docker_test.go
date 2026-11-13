package container

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/builtin/kri/container/ocienv"
	"kevaso.com/core/builtin/kri/hostexec"
	"kevaso.com/core/sdk/kri"
)

// TestSecretArgsOnARealEngine runs a real container with the secret arguments the runtime gives
// one (secretArgs: the folder read-only, the env file) and checks what the engine does with them:
// the file is there with its mode, a rotation (a file renamed over it, as the host writes) shows
// inside without a restart, the container can't write in that folder (but can in its own /run),
// the variable is its command's, and what `docker inspect` shows: the folder, never a file's value
// — and, which Docker can't avoid, the variable's value.
//
// The runtime itself is Linux-only (nsenter, ip, mount: it's root on the host), so this doesn't
// make the tmpfs: a temporary folder stands in for it. Opt in with KEVASO_DOCKER_TEST=1 (Docker
// running, debian:bookworm-slim present); the container is removed at the end.
func TestSecretArgsOnARealEngine(t *testing.T) {
	if os.Getenv("KEVASO_DOCKER_TEST") != "1" {
		t.Skip("KEVASO_DOCKER_TEST=1 runs it against the local docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	old := SecretsDir
	SecretsDir = t.TempDir()
	defer func() { SecretsDir = old }()
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	id := kri.ID{Namespace: "test", Name: "secrets-" + hex.EncodeToString(b), UID: hex.EncodeToString(b)}
	_, files, envFile := SecretsPaths(id)
	host := hostexec.Local{}
	if err := host.WriteFile(files+"/run/secrets/tls.pem", []byte("KEY-1"), 0o400); err != nil {
		t.Fatal(err)
	}
	const token = "tok en=1 'x'"
	if err := host.WriteFile(envFile, envFileText([]kri.SecretEnv{{Name: "LEGACY_TOKEN", Value: []byte(token)}}), 0o600); err != nil {
		t.Fatal(err)
	}
	s := state{ID: id, Secrets: &secretState{Files: []string{"/run/secrets/tls.pem"}, Dirs: []string{"/run/secrets"}, Env: []string{"LEGACY_TOKEN=legacy-token@1"}}}
	docker := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return strings.TrimSpace(out.String()), err
	}
	name := "kv-" + id.Name
	// --pull never, as the runtime runs it: the image must be there first.
	if out, err := docker("pull", "-q", "debian:bookworm-slim"); err != nil {
		t.Fatalf("docker pull debian:bookworm-slim: %v: %s", err, out)
	}
	args := append([]string{"run", "-d", "--name", name, "--pull", "never", "--tmpfs", "/run:rw,nosuid,nodev,mode=0755"}, secretArgs(s)...)
	args = append(args, "debian:bookworm-slim", "sleep", "300")
	if out, err := docker(args...); err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	defer func() { _, _ = docker("rm", "-f", name) }()
	in := func(script string) (string, error) { return docker("exec", name, "sh", "-c", script) }
	if out, err := in("cat /run/secrets/tls.pem; echo; stat -c %a /run/secrets/tls.pem"); err != nil || out != "KEY-1\n400" {
		t.Fatalf("the file: %q %v", out, err)
	}
	if out, err := in(`printf %s "$LEGACY_TOKEN"`); err != nil || out != token {
		t.Fatalf("the variable: %q %v", out, err)
	}
	if out, err := in("touch /run/secrets/planted"); err == nil || !strings.Contains(out, "Read-only") {
		t.Fatalf("the container wrote in its secrets folder: %q %v", out, err)
	}
	if out, err := in("touch /run/mine && grep ' /run ' /proc/mounts"); err != nil || !strings.Contains(out, "tmpfs") {
		t.Fatalf("its own /run: %q %v", out, err)
	}
	started, _ := docker("inspect", "--format", "{{.State.StartedAt}}", name)

	// Rotated as the host writes it (a new file renamed over the old): seen inside, no restart.
	if err := host.WriteFile(files+"/run/secrets/tls.pem", []byte("KEY-2"), 0o400); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, _ := in("cat /run/secrets/tls.pem")
		if out == "KEY-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not rotated in place: %q", out)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if now, _ := docker("inspect", "--format", "{{.State.StartedAt}}", name); now != started {
		t.Fatalf("restarted: %s, was %s", now, started)
	}
	// What someone with the host's docker sees: the folder, no file's value; the variable's value.
	inspect, err := docker("inspect", name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(inspect, "KEY-") {
		t.Fatal("a file's value in docker inspect")
	}
	if !strings.Contains(inspect, files+"/run/secrets") {
		t.Fatal("the mount's folder isn't in docker inspect")
	}
	if !strings.Contains(inspect, "LEGACY_TOKEN=tok en=1") {
		t.Fatal("docker inspect no longer shows env values: the ADR 0009 addendum and the admission warning can say less")
	}
}

// TestEnvRuntimeOnRealDocker is the real thing, on a Linux host as root whose Docker has
// kevaso-oci registered (this runtime's Install did it): a container started through it has the
// variable in its process's environment, and neither `docker inspect` nor any file under the
// engine's container folder or containerd's metadata has its value (ocienv.VerifyDocker, which
// the bare-metal suite calls too). Opt in with KEVASO_DOCKER_TEST=1.
func TestEnvRuntimeOnRealDocker(t *testing.T) {
	if os.Getenv("KEVASO_DOCKER_TEST") != "1" {
		t.Skip("KEVASO_DOCKER_TEST=1 runs it against the local docker")
	}
	if goruntime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs a Linux host's own Docker, as root (Docker Desktop's daemon can't register a runtime)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{json .Runtimes}}").Output()
	if err != nil || !strings.Contains(string(out), `"`+ocienv.RuntimeName+`"`) {
		t.Skipf("Docker here doesn't have %s registered (kevasod's docker runtime installs it): %s %v", ocienv.RuntimeName, out, err)
	}
	if err := ocienv.VerifyDocker(ctx, ocienv.Check{}); err != nil {
		t.Fatal(err)
	}
}
