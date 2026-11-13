package container

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/container/ocienv"
	"kevaso.com/core/sdk/kri"
)

// daemon.json: Kevaso's keys set, its runtime registered or removed, everything else kept; no
// restart when nothing changed, however the file is laid out.
func TestDockerDaemonConfig(t *testing.T) {
	theirs := `{"log-driver":"journald","default-ulimits":{"nofile":{"Name":"nofile","Hard":65536,"Soft":65536}},
	  "runtimes":{"nvidia":{"path":"/usr/bin/nvidia-container-runtime","runtimeArgs":[]}},"iptables":true}`
	next, changed := DockerDaemonConfig([]byte(theirs), true)
	if !changed {
		t.Fatal("not changed")
	}
	var m struct {
		LogDriver      string                    `json:"log-driver"`
		Ulimits        map[string]map[string]any `json:"default-ulimits"`
		Runtimes       map[string]map[string]any `json:"runtimes"`
		IPTables       *bool                     `json:"iptables"`
		IP6Tables      *bool                     `json:"ip6tables"`
		Bridge         string                    `json:"bridge"`
		LiveRestore    bool                      `json:"live-restore"`
		DefaultRuntime string                    `json:"default-runtime"`
	}
	if err := json.Unmarshal(next, &m); err != nil {
		t.Fatal(err)
	}
	if m.LogDriver != "journald" || m.Ulimits["nofile"]["Hard"] != float64(65536) || m.Runtimes["nvidia"]["path"] != "/usr/bin/nvidia-container-runtime" {
		t.Fatalf("their settings lost: %s", next)
	}
	if *m.IPTables || *m.IP6Tables || m.Bridge != "none" || !m.LiveRestore || m.Runtimes[ocienv.RuntimeName]["path"] != ocienv.ShimPath {
		t.Fatalf("ours not set: %s", next)
	}
	if !strings.Contains(string(next), `"Hard": 65536`) {
		t.Fatalf("a number rewritten: %s", next)
	}
	if again, changed := DockerDaemonConfig(next, true); changed || string(again) != string(next) {
		t.Fatal("the same config changed")
	}
	compact, _ := json.Marshal(json.RawMessage(next))
	if _, changed := DockerDaemonConfig(compact, true); changed {
		t.Fatal("another layout of the same config counted as a change")
	}
	off, changed := DockerDaemonConfig(next, false)
	if !changed || strings.Contains(string(off), ocienv.RuntimeName) || !strings.Contains(string(off), "nvidia") {
		t.Fatalf("unregistering: %s", off)
	}
	bare, _ := DockerDaemonConfig(nil, false)
	if strings.Contains(string(bare), "runtimes") {
		t.Fatalf("an empty runtimes: %s", bare)
	}
	if _, changed := DockerDaemonConfig([]byte("{not json"), false); !changed {
		t.Fatal("a broken file kept")
	}
}

// dockerHost is a fake host whose dockerd takes kevaso-oci (rootful, runc, API 1.45).
func dockerHost() *fake {
	f := newFake()
	f.replies = map[string]string{
		"sh -c command -v runc":   "/usr/sbin/runc\n",
		"docker info --format":    "runc\n{\"io.containerd.runc.v2\":{\"path\":\"runc\"},\"kevaso-oci\":{\"path\":\"" + ocienv.ShimPath + "\"},\"runc\":{\"path\":\"runc\"}}\n[\"name=apparmor\",\"name=seccomp,profile=builtin\",\"name=cgroupns\"]\n",
		"docker version --format": "1.45\n",
	}
	return f
}

func TestInstallRegistersTheRuntime(t *testing.T) {
	ctx := context.Background()
	f := dockerHost()
	r := runtime(t, f)
	if err := r.Install(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !r.Info().Capabilities.EnvOutsideEngine {
		_, why := r.envShimNow()
		t.Fatalf("not through the runtime: %s", why)
	}
	var cfg ocienv.Config
	if err := json.Unmarshal(f.files[ocienv.ConfigPath], &cfg); err != nil || cfg.Runtime != "/usr/sbin/runc" || f.modes[ocienv.ConfigPath] != 0o644 {
		t.Fatalf("its configuration %q (%v)", f.files[ocienv.ConfigPath], err)
	}
	if got := f.last("ln "); got != "ln -sfn "+r.Self+" "+ocienv.ShimPath {
		t.Fatalf("link: %q", got)
	}
	if !strings.Contains(string(f.files["/etc/docker/daemon.json"]), `"path": "`+ocienv.ShimPath+`"`) {
		t.Fatalf("daemon.json %s", f.files["/etc/docker/daemon.json"])
	}
}

// Where the host can't take it, env secrets go through --env-file, and the runtime says why.
func TestInstallFallsBack(t *testing.T) {
	for _, c := range []struct {
		name     string
		setup    func(f *fake)
		engine   string
		why      string
		register bool
	}{
		{"rootless docker", func(f *fake) {
			f.replies["docker info --format"] = "runc\n{\"kevaso-oci\":{}}\n[\"name=seccomp,profile=builtin\",\"name=rootless\",\"name=cgroupns\"]\n"
		}, "docker", "rootless", true},
		{"gVisor as the default", func(f *fake) {
			f.files["/etc/docker/daemon.json"] = []byte(`{"default-runtime":"runsc","runtimes":{"runsc":{"path":"/usr/bin/runsc"}}}`)
		},
			"docker", "runsc, not runc", false},
		{"kata as dockerd's default (set elsewhere)", func(f *fake) { f.replies["docker info --format"] = "kata\n{\"kevaso-oci\":{}}\n[]\n" }, "docker", "kata, not runc", true},
		{"registration didn't take", func(f *fake) { f.replies["docker info --format"] = "runc\n{\"runc\":{}}\n[]\n" }, "docker", "isn't among its runtimes", true},
		{"docker older than 24", func(f *fake) { f.replies["docker version --format"] = "1.41\n" }, "docker", "older than 1.43", true},
		{"no runc", func(f *fake) { delete(f.replies, "sh -c command -v runc") }, "docker", "runc isn't on the host's PATH", false},
		{"podman", func(*fake) {}, "podman", "podman writes the container's OCI config", false},
	} {
		f := dockerHost()
		c.setup(f)
		r := runtime(t, f)
		r.Engine = c.engine
		if err := r.Install(context.Background(), nil); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		shim, why := r.envShimNow()
		if shim || !strings.Contains(why, c.why) || r.Info().Capabilities.EnvOutsideEngine {
			t.Errorf("%s: shim %v, why %q", c.name, shim, why)
		}
		if c.engine == "docker" && strings.Contains(string(f.files["/etc/docker/daemon.json"]), ocienv.RuntimeName) != c.register {
			t.Errorf("%s: daemon.json %s", c.name, f.files["/etc/docker/daemon.json"])
		}
	}
}

// Through the runtime: a silo with env deliveries is made with --runtime kevaso-oci and the
// annotation (its short id, no value) instead of --env-file; one without keeps the engine's
// default; a rotated variable waits for the next start but needs no remake (each start reads the
// file); the env file must be there at every start; a host that loses the runtime makes the silo
// afresh with --env-file.
func TestEnvThroughTheRuntime(t *testing.T) {
	ctx := context.Background()
	f := dockerHost()
	r := runtime(t, f)
	if err := r.Install(ctx, nil); err != nil {
		t.Fatal(err)
	}
	other := kri.ID{Namespace: "shop", Name: "web", UID: "u2"}
	for _, id := range []kri.ID{silo, other} {
		if err := r.Create(ctx, kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, envFile := SecretsPaths(silo)
	token := func(v string, ver int64) kri.SecretEnv {
		return kri.SecretEnv{Secret: "legacy-token", Name: "LEGACY_TOKEN", Value: []byte(v), Version: ver}
	}
	set := func(id kri.ID, sec kri.Secrets) string {
		t.Helper()
		p, err := r.SetSecrets(ctx, id, sec)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	set(silo, kri.Secrets{Env: []kri.SecretEnv{token("tok-1", 1)}})
	set(other, kri.Secrets{Files: []kri.SecretFile{{Secret: "k", Path: "/run/secrets/k", Value: []byte("K"), Version: 1}}})
	for _, id := range []kri.ID{silo, other} {
		if err := r.Start(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	n := NamesFor(silo)
	main := f.last("docker run -d --name " + n.Main)
	if !strings.Contains(main, "--runtime kevaso-oci --annotation kevaso.com/env-secrets="+n.Short) || strings.Contains(main, "--env-file") {
		t.Fatalf("main container: %q", main)
	}
	if plain := f.last("docker run -d --name " + NamesFor(other).Main); strings.Contains(plain, "--runtime") || strings.Contains(plain, "--annotation") {
		t.Fatalf("a silo without env secrets: %q", plain)
	}
	if in, _ := r.EnvInEngine(silo); in {
		t.Fatal("EnvInEngine for a silo through the runtime")
	}
	if in, _ := r.EnvInEngine(other); !in {
		t.Fatal("a silo without env through the runtime") // (nothing to keep out: it reports the host's default)
	}
	if _, err := r.RunInit(ctx, silo, kri.InitStep{Name: "one", Run: "true"}, nil); err != nil {
		t.Fatal(err)
	}
	if init := f.last("docker run --rm --name " + n.Init); !strings.Contains(init, "--runtime kevaso-oci") {
		t.Fatalf("init container: %q", init)
	}
	for _, c := range f.cmds {
		if strings.Contains(c, "tok-") {
			t.Fatalf("a value on a command line: %q", c)
		}
	}

	// Rotated while it runs: at the next start, by a plain start, not a new container.
	if p := set(silo, kri.Secrets{Env: []kri.SecretEnv{token("tok-2", 2)}}); p != "environment variables take effect at the next start" {
		t.Fatalf("pending %q", p)
	}
	if string(f.files[envFile]) != "LEGACY_TOKEN=tok-2\n" {
		t.Fatalf("env file %q", f.files[envFile])
	}
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.files[envFile]; ok {
		t.Fatal("the env file outlived the stop")
	}
	// The agent sets them before each start; without them it doesn't start (kevaso-oci would refuse).
	if err := r.Start(ctx, silo); err == nil || !strings.Contains(err.Error(), "env secrets aren't on the host") {
		t.Fatalf("started without its env file: %v", err)
	}
	set(silo, kri.Secrets{Env: []kri.SecretEnv{token("tok-2", 2)}})
	before := len(f.cmds)
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.cmds[before:] {
		if strings.HasPrefix(c, "docker rm") || strings.HasPrefix(c, "docker run") {
			t.Fatalf("made afresh for a rotated variable through the runtime: %q", c)
		}
	}
	if f.last("docker start") != "docker start "+n.Main {
		t.Fatal("not started")
	}
	if s, _ := r.load(silo); s.Secrets.pending() != "" {
		t.Fatalf("still pending after the start: %q", s.Secrets.pending())
	}

	// The host loses the runtime (podman now, a failed registration): made afresh with --env-file.
	r.setEnvPath(false, "Docker didn't take Kevaso's OCI runtime")
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	set(silo, kri.Secrets{Env: []kri.SecretEnv{token("tok-2", 2)}})
	if in, why := r.EnvInEngine(silo); !in || !strings.Contains(why, "didn't take") {
		t.Fatalf("EnvInEngine %v %q", in, why)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if again := f.last("docker run -d --name " + n.Main); !strings.Contains(again, "--env-file "+envFile) || strings.Contains(again, "--runtime") {
		t.Fatalf("after the runtime went: %q", again)
	}

	// Back through the runtime, then no env secrets at all: made afresh without the annotation
	// (kevaso-oci would refuse to start it without its env file).
	r.setEnvPath(true, "")
	_ = r.Stop(ctx, silo)
	set(silo, kri.Secrets{Env: []kri.SecretEnv{token("tok-2", 2)}})
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	_ = r.Stop(ctx, silo)
	set(silo, kri.Secrets{})
	before = len(f.cmds)
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := f.last("docker run -d --name " + n.Main); len(f.cmds) == before || strings.Contains(got, "--runtime") || strings.Contains(got, "--annotation") {
		t.Fatalf("without env secrets: %q", got)
	}
}

// Before Install has decided (kevasod just started), a silo keeps the way it had.
func TestEnvWayKeptBeforeInstall(t *testing.T) {
	r := &Runtime{}
	if got := r.viaFor(secretState{EnvVia: viaRuntime}); got != viaRuntime {
		t.Fatalf("got %q", got)
	}
	if got := r.viaFor(secretState{}); got != viaEnvFile {
		t.Fatalf("got %q", got)
	}
	r.setEnvPath(false, "x")
	if got := r.viaFor(secretState{EnvVia: viaRuntime}); got != viaEnvFile {
		t.Fatalf("got %q", got)
	}
}

// A value the OCI config (JSON) can't carry is refused through the runtime, not mangled.
func TestEnvThroughTheRuntimeRefusesNonUTF8(t *testing.T) {
	ctx := context.Background()
	f := dockerHost()
	r := runtime(t, f)
	if err := r.Install(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	_, err := r.SetSecrets(ctx, silo, kri.Secrets{Env: []kri.SecretEnv{{Secret: "bin", Name: "BIN", Value: []byte{0xff, 0x00, 0x01}}}})
	if err == nil {
		t.Fatal("accepted")
	}
	_, err = r.SetSecrets(ctx, silo, kri.Secrets{Env: []kri.SecretEnv{{Secret: "bin", Name: "BIN", Value: []byte{0xff, 0x01}}}})
	if err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("got %v", err)
	}
}
