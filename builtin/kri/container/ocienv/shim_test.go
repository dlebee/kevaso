package ocienv

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "v4lue-NEVER-in-a-log"

type world struct {
	t       *testing.T
	shim    *Shim
	bundle  string
	secrets string
	stderr  bytes.Buffer
	execd   []string // the real runtime's argv, when it was exec'd
	env     []string
	inMem   bool
}

// newWorld is a host in a temporary folder: the configuration naming the real runtime, a secrets
// folder with one silo's env file, a bundle whose config.json carries that silo's annotation.
func newWorld(t *testing.T) *world {
	root := t.TempDir()
	w := &world{t: t, bundle: filepath.Join(root, "bundle"), secrets: filepath.Join(root, "secrets"), inMem: true}
	must(t, os.MkdirAll(filepath.Join(w.secrets, "0123456789"), 0o700))
	must(t, os.Chmod(w.secrets, 0o700))
	must(t, os.WriteFile(filepath.Join(w.secrets, "0123456789", "env"), []byte("APP_TOKEN="+secret+"\n"), 0o600))
	must(t, os.Mkdir(w.bundle, 0o700))
	must(t, os.WriteFile(filepath.Join(w.bundle, "config.json"), []byte(dockerConfig), 0o640))
	cfg := filepath.Join(root, "oci-runtime.json")
	must(t, os.WriteFile(cfg, []byte(`{"runtime":"/usr/sbin/runc"}`), 0o644))
	w.shim = &Shim{ConfigPath: cfg, SecretsDir: w.secrets, Owner: os.Getuid(), Stderr: &w.stderr,
		Exec: func(path string, argv, env []string) error {
			if path != argv[0] {
				t.Errorf("argv[0] %q for %q", argv[0], path)
			}
			w.execd, w.env = argv, env
			return nil
		},
		InMemory: func(string) (bool, string, error) { return w.inMem, "ext4", nil },
	}
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (w *world) create() []string {
	return []string{"--root", "/var/run/docker/runtime-runc/moby", "--log", filepath.Join(w.bundle, "log.json"), "--log-format", "json",
		"create", "--bundle", w.bundle, "--pid-file", filepath.Join(w.bundle, "init.pid"), "3f2a"}
}

func (w *world) run(args []string) int {
	return w.shim.Run(args, []string{"PATH=/usr/bin", "XDG_RUNTIME_DIR=/run/user/0"})
}

func (w *world) env0() []string {
	b, err := os.ReadFile(filepath.Join(w.bundle, "config.json"))
	must(w.t, err)
	var c struct {
		Process struct{ Env []string } `json:"process"`
	}
	must(w.t, json.Unmarshal(b, &c))
	return c.Process.Env
}

func TestCreateSetsTheVariables(t *testing.T) {
	w := newWorld(t)
	args := w.create()
	if code := w.run(args); code != 0 {
		t.Fatalf("exit %d: %s", code, w.stderr.String())
	}
	if strings.Join(w.execd, " ") != "/usr/sbin/runc "+strings.Join(args, " ") {
		t.Fatalf("exec'd %q", w.execd)
	}
	if strings.Join(w.env, " ") != "PATH=/usr/bin XDG_RUNTIME_DIR=/run/user/0" {
		t.Fatalf("environment changed: %q", w.env)
	}
	env := w.env0()
	if !contains(env, "APP_TOKEN="+secret) || contains(env, "APP_TOKEN=from-the-image") || !contains(env, "HOSTNAME=api") {
		t.Fatalf("process.env %q", env)
	}
	fi, _ := os.Stat(filepath.Join(w.bundle, "config.json"))
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(w.bundle, ".config.json.kevaso-*")); len(left) > 0 {
		t.Fatalf("left behind: %v", left)
	}
	if strings.Contains(w.stderr.String(), secret) {
		t.Fatal("a value on stderr")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Every other action, and any container that isn't a silo with env secrets, goes straight on.
func TestPassThrough(t *testing.T) {
	for _, args := range [][]string{
		{"--root", "/r", "start", "3f2a"},
		{"--root", "/r", "--log", "/l", "--log-format", "json", "exec", "--process", "/tmp/runc-process1", "--detach", "3f2a"},
		{"--root", "/r", "delete", "--force", "3f2a"},
		{"--root", "/r", "kill", "--all", "3f2a", "9"},
		{"--root", "/r", "state", "3f2a"},
		{"--version"},
		{"features"},
	} {
		w := newWorld(t)
		before, _ := os.ReadFile(filepath.Join(w.bundle, "config.json"))
		if code := w.run(args); code != 0 || strings.Join(w.execd[1:], " ") != strings.Join(args, " ") {
			t.Fatalf("%v: exit %d, exec'd %q: %s", args, code, w.execd, w.stderr.String())
		}
		after, _ := os.ReadFile(filepath.Join(w.bundle, "config.json"))
		if !bytes.Equal(before, after) {
			t.Fatalf("%v touched the config", args)
		}
	}
	// No annotation: an ordinary container on the host, untouched (even with no env file anywhere).
	w := newWorld(t)
	plain := strings.Replace(dockerConfig, `"kevaso.com/env-secrets":"0123456789",`, "", 1)
	must(t, os.WriteFile(filepath.Join(w.bundle, "config.json"), []byte(plain), 0o644))
	must(t, os.RemoveAll(w.secrets))
	if code := w.run(w.create()); code != 0 {
		t.Fatalf("exit %d: %s", code, w.stderr.String())
	}
	if after, _ := os.ReadFile(filepath.Join(w.bundle, "config.json")); string(after) != plain {
		t.Fatal("an ordinary container's config changed")
	}
}

// A silo that should have variables and can't get them isn't started, and says why where the
// engine reads it (stderr and the runtime's json log), without a value.
func TestFailsClosed(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(w *world)
		want  string
	}{
		{"no env file", func(w *world) { must(t, os.Remove(filepath.Join(w.secrets, "0123456789", "env"))) }, "no such file"},
		{"the env file a link", func(w *world) {
			p := filepath.Join(w.secrets, "0123456789", "env")
			must(t, os.Rename(p, p+".real"))
			must(t, os.Symlink(p+".real", p))
		}, "is a link"},
		{"the silo's folder a link", func(w *world) {
			d := filepath.Join(w.secrets, "0123456789")
			must(t, os.Rename(d, d+"x"))
			must(t, os.Symlink(d+"x", d))
		}, "isn't a folder"},
		{"readable by others", func(w *world) { must(t, os.Chmod(filepath.Join(w.secrets, "0123456789", "env"), 0o644)) }, "mode 0644"},
		{"the secrets folder writable by others", func(w *world) { must(t, os.Chmod(w.secrets, 0o777)) }, "mode 0777"},
		{"another owner", func(w *world) { w.shim.Owner = os.Getuid() + 1 }, "owned by uid"},
		{"two links to the env file", func(w *world) {
			p := filepath.Join(w.secrets, "0123456789", "env")
			must(t, os.Link(p, filepath.Join(w.secrets, "0123456789", "other")))
		}, "has 2 links"},
		{"a bad line", func(w *world) {
			must(t, os.WriteFile(filepath.Join(w.secrets, "0123456789", "env"), []byte("APP_TOKEN="+secret+"\n"+secret+"\n"), 0o600))
		}, "line 2 isn't NAME=VALUE"},
		{"an annotation that isn't a short id", func(w *world) {
			must(t, os.WriteFile(filepath.Join(w.bundle, "config.json"), []byte(strings.Replace(dockerConfig, "0123456789", "../../etc", 1)), 0o644))
		}, "isn't a silo's short id"},
		{"the bundle on disk", func(w *world) { w.inMem = false }, "not in memory"},
		{"no process", func(w *world) {
			must(t, os.WriteFile(filepath.Join(w.bundle, "config.json"), []byte(`{"annotations":{"kevaso.com/env-secrets":"0123456789"}}`), 0o644))
		}, "no process"},
		{"no configuration", func(w *world) { w.shim.ConfigPath += ".gone" }, "its configuration"},
		{"the configuration names this runtime", func(w *world) {
			must(t, os.WriteFile(w.shim.ConfigPath, []byte(`{"runtime":"/usr/local/lib/kevaso/kevaso-oci"}`), 0o644))
		}, "is this one"},
		{"a relative real runtime", func(w *world) { must(t, os.WriteFile(w.shim.ConfigPath, []byte(`{"runtime":"runc"}`), 0o644)) }, "absolute"},
		{"the configuration writable by others", func(w *world) { must(t, os.Chmod(w.shim.ConfigPath, 0o666)) }, "mode 0666"},
	} {
		w := newWorld(t)
		c.setup(w)
		before, _ := os.ReadFile(filepath.Join(w.bundle, "config.json"))
		code := w.run(w.create())
		if code == 0 || w.execd != nil {
			t.Errorf("%s: exit %d, exec'd %q", c.name, code, w.execd)
			continue
		}
		if !strings.Contains(w.stderr.String(), c.want) || !strings.HasPrefix(w.stderr.String(), "kevaso-oci: ") {
			t.Errorf("%s: stderr %q, want %q", c.name, w.stderr.String(), c.want)
		}
		log, _ := os.ReadFile(filepath.Join(w.bundle, "log.json"))
		var line struct{ Level, Msg string }
		if err := json.Unmarshal(bytes.TrimSpace(log), &line); err != nil || line.Level != "error" || !strings.Contains(line.Msg, c.want) {
			t.Errorf("%s: log %q", c.name, log)
		}
		if strings.Contains(w.stderr.String()+string(log), secret) {
			t.Errorf("%s: a value in the message", c.name)
		}
		if after, _ := os.ReadFile(filepath.Join(w.bundle, "config.json")); !bytes.Equal(before, after) {
			t.Errorf("%s: the config changed", c.name)
		}
	}
}

func TestExecFailureIsReported(t *testing.T) {
	w := newWorld(t)
	w.shim.Exec = func(string, []string, []string) error { return errors.New("no such file") }
	if code := w.run([]string{"state", "x"}); code == 0 || !strings.Contains(w.stderr.String(), "exec /usr/sbin/runc") {
		t.Fatalf("exit %d: %s", code, w.stderr.String())
	}
}

// The text log format, for a runtime called without --log-format json.
func TestFailureTextLog(t *testing.T) {
	w := newWorld(t)
	must(t, os.Remove(filepath.Join(w.secrets, "0123456789", "env")))
	log := filepath.Join(w.bundle, "log")
	if code := w.run([]string{"--log", log, "create", "--bundle", w.bundle, "c1"}); code == 0 {
		t.Fatal("started")
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "level=error msg=") {
		t.Fatalf("log %q", b)
	}
}
