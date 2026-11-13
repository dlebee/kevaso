package container

import (
	"context"
	"slices"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

func TestSecretDirs(t *testing.T) {
	got := SecretDirs([]string{"/run/secrets/b", "/run/app/key", "/run/secrets/a", "/run/secrets/x/y", "/run/application/k"})
	want := []string{"/run/app", "/run/application", "/run/secrets"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !covered([]string{"/run/secrets/x"}, []string{"/run/secrets"}) || covered([]string{"/run/app"}, []string{"/run/application"}) {
		t.Fatal("covered")
	}
}

// The plan the runtime builds for a container's file and env secrets: a tmpfs of the host's per
// silo, the files in it and their folders mounted read-only, the variables in an env file of the
// same tmpfs given to the engine, no value on any command line; a rotated file in place, a
// rotated variable at the next start (the main container made afresh); values off the host when
// stopped; everything gone on Delete.
func TestSecretsPlan(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	tmpfs, files, envFile := SecretsPaths(silo)
	set := func(sec kri.Secrets) string {
		t.Helper()
		pending, err := r.SetSecrets(ctx, silo, sec)
		if err != nil {
			t.Fatal(err)
		}
		return pending
	}
	tls := func(v string, ver int64) kri.SecretFile {
		return kri.SecretFile{Secret: "tls-key", Path: "/run/secrets/tls.pem", Mode: 0o400, Value: []byte(v), Version: ver}
	}
	token := func(v string, ver int64) kri.SecretEnv {
		return kri.SecretEnv{Secret: "legacy-token", Name: "LEGACY_TOKEN", Value: []byte(v), Version: ver}
	}
	// Before the main container exists: nothing pends, all of it goes in when it's made.
	if p := set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-1", 1)}, Env: []kri.SecretEnv{token("tok en=1", 1)}}); p != "" {
		t.Fatalf("pending %q before the container exists", p)
	}
	if got := f.last("mount "); got != "mount -t tmpfs -o size=16m,mode=0700,uid=0,gid=0,nosuid,nodev,noexec kevaso-secrets "+tmpfs {
		t.Fatalf("mount: %q", got)
	}
	if string(f.files[files+"/run/secrets/tls.pem"]) != "KEY-1" || f.modes[files+"/run/secrets/tls.pem"] != 0o400 {
		t.Fatalf("file %q mode %v", f.files[files+"/run/secrets/tls.pem"], f.modes[files+"/run/secrets/tls.pem"])
	}
	if string(f.files[envFile]) != "LEGACY_TOKEN=tok en=1\n" || f.modes[envFile] != 0o600 {
		t.Fatalf("env file %q mode %v", f.files[envFile], f.modes[envFile])
	}
	s, _ := r.load(silo)
	if b := f.files[statePath(silo)]; strings.Contains(string(b), "KEY-1") || strings.Contains(string(b), "tok en") || !strings.Contains(string(s.Secrets.Env[0]), "LEGACY_TOKEN=legacy-token@1") {
		t.Fatalf("state: %s", b)
	}

	// Init containers and the main container get the folder read-only and the env file.
	n := NamesFor(silo)
	if _, err := r.RunInit(ctx, silo, kri.InitStep{Name: "one", Run: "cat /run/secrets/tls.pem"}, nil); err != nil {
		t.Fatal(err)
	}
	mount := "--mount type=bind,src=" + files + "/run/secrets,dst=/run/secrets,readonly --env-file " + envFile
	if got := f.last("docker run --rm --name " + n.Init); !strings.Contains(got, mount) {
		t.Fatalf("init container: %q", got)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := f.last("docker run -d --name " + n.Main); !strings.Contains(got, mount) || !strings.Contains(got, "--tmpfs /run:rw,nosuid,nodev,mode=0755") {
		t.Fatalf("main container: %q", got)
	}
	noValues := func() {
		t.Helper()
		for _, c := range f.cmds {
			for _, v := range []string{"KEY-", "tok en"} {
				if strings.Contains(c, v) {
					t.Fatalf("a value on a command line: %q", c)
				}
			}
		}
	}
	noValues()

	// A rotated file: in place, nothing restarted.
	runs := len(f.cmds)
	if p := set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-2", 2)}, Env: []kri.SecretEnv{token("tok en=1", 1)}}); p != "" {
		t.Fatalf("pending %q for a rotated file", p)
	}
	if string(f.files[files+"/run/secrets/tls.pem"]) != "KEY-2" {
		t.Fatal("not rotated")
	}
	for _, c := range f.cmds[runs:] {
		if strings.HasPrefix(c, "docker rm") || strings.HasPrefix(c, "docker run") || strings.HasPrefix(c, "docker stop") {
			t.Fatalf("restarted for a rotated file: %q", c)
		}
	}
	// A file in a folder it doesn't have, and a rotated variable: at the next start.
	key := kri.SecretFile{Secret: "app-key", Path: "/run/app/key", Value: []byte("KEY-app"), Version: 1}
	p := set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-2", 2), key}, Env: []kri.SecretEnv{token("tok en=2", 2)}})
	if p != "environment variables and files in a folder not mounted yet take effect at the next start" {
		t.Fatalf("pending %q", p)
	}
	if string(f.files[files+"/run/app/key"]) != "KEY-app" || f.modes[files+"/run/app/key"] != 0o400 {
		t.Fatal("app key")
	}
	// Stopped: no value left on the host.
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{files + "/run/secrets/tls.pem", files + "/run/app/key", envFile} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s still on the host after stop", p)
		}
	}
	if err := r.Start(ctx, silo); err == nil || !strings.Contains(err.Error(), "isn't on the host") {
		t.Fatalf("started without its secrets: %v", err)
	}
	set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-2", 2), key}, Env: []kri.SecretEnv{token("tok en=2", 2)}})
	runs = len(f.cmds)
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	made := strings.Join(f.cmds[runs:], "\n")
	if !strings.Contains(made, "docker rm -f "+n.Main) || !strings.Contains(made, "--mount type=bind,src="+files+"/run/app,dst=/run/app,readonly") {
		t.Fatalf("not made afresh with its new secrets:\n%s", made)
	}
	if p := set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-2", 2), key}, Env: []kri.SecretEnv{token("tok en=2", 2)}}); p != "" {
		t.Fatalf("pending %q after the new start", p)
	}
	// Stopped and started with nothing changed: the same container.
	_ = r.Stop(ctx, silo)
	set(kri.Secrets{Files: []kri.SecretFile{tls("KEY-2", 2), key}, Env: []kri.SecretEnv{token("tok en=2", 2)}})
	runs = len(f.cmds)
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.cmds[runs:], "\n"); strings.Contains(got, "docker rm") || !strings.Contains(got, "docker start "+n.Main) {
		t.Fatalf("restart: %s", got)
	}
	noValues()

	// The grant goes: its files and the env file go from the host (the variable from the
	// container at its next start).
	if p := set(kri.Secrets{}); p != "environment variables take effect at the next start" {
		t.Fatalf("pending %q", p)
	}
	for _, p := range []string{files + "/run/secrets/tls.pem", files + "/run/app/key", envFile} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s still on the host", p)
		}
	}
	// Deleted: the tmpfs unmounted and gone.
	if err := r.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := f.last("umount"); got != "umount "+tmpfs {
		t.Fatalf("umount: %q", got)
	}
	if strings.Contains(string(f.files["/proc/self/mounts"]), tmpfs) {
		t.Fatal("still mounted")
	}
}

func TestSecretsRefused(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		engine string
		sec    kri.Secrets
		want   string
	}{
		{"docker", kri.Secrets{Files: []kri.SecretFile{{Secret: "a", Path: "/run/a"}}}, "not in /run itself"},
		{"docker", kri.Secrets{Files: []kri.SecretFile{{Secret: "a", Path: "/etc/a"}}}, "under /run/"},
		{"docker", kri.Secrets{Files: []kri.SecretFile{{Secret: "a", Path: "/run/s/../a"}}}, "clean path"},
		{"docker", kri.Secrets{Env: []kri.SecretEnv{{Secret: "a", Name: "A", Value: []byte("x\ny")}}}, "newline"},
		{"docker", kri.Secrets{Env: []kri.SecretEnv{{Secret: "a", Name: "1A", Value: []byte("x")}}}, "isn't a variable name"},
		{"podman", kri.Secrets{Env: []kri.SecretEnv{{Secret: "a", Name: "A", Value: []byte(`"x"`)}}}, "starts with a quote"},
	} {
		f := newFake()
		r := runtime(t, f)
		r.Engine = tc.engine
		if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.SetSecrets(ctx, silo, tc.sec); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%v: %v, want %q", tc.sec, err, tc.want)
		}
	}
	// A quote is fine on docker, which takes the value as it is.
	f := newFake()
	r := runtime(t, f)
	_ = r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"})
	if _, err := r.SetSecrets(ctx, silo, kri.Secrets{Env: []kri.SecretEnv{{Secret: "a", Name: "A", Value: []byte(`"x"`)}}}); err != nil {
		t.Fatal(err)
	}
}

// A silo without file or env secrets: no tmpfs, no mounts, nothing in its run.
func TestNoSecretsNoMounts(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := runtime(t, f)
	_ = r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"})
	if p, err := r.SetSecrets(ctx, silo, kri.Secrets{}); err != nil || p != "" {
		t.Fatal(p, err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "mount") || strings.Contains(c, "--env-file") || strings.Contains(c, "--mount") {
			t.Fatalf("%q", c)
		}
	}
}
