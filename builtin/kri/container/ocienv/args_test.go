package ocienv

import (
	"strings"
	"testing"
)

// The command lines are the ones the engines really build, field for field:
//
//   - containerd's runc shim (containerd-shim-runc-v2) calls the runtime through go-runc:
//     github.com/containerd/go-runc runc.go, (*Runc).args (global flags in this order: --root,
//     --debug, --log, --log-format, --systemd-cgroup, --rootless=BOOL), Create ("create --bundle B"
//     then CreateOpts.args: --pid-file, --console-socket, --pidfd-socket, --no-pivot,
//     --no-new-keyring, --detach, --preserve-fds), Exec ("exec --process FILE" then ExecOpts.args:
//     --console-socket, --pidfd-socket, --detach, --pid-file), Start, Delete (--force), Kill (--all),
//     State. Docker's runtimes get Root <exec-root>/runtime-runc (moby daemon/runtime_unix.go,
//     defaultV2ShimConfig), to which the shim adds the namespace (moby); the bundle is containerd's
//     state dir (core/runtime/v2/bundle.go: <state>/<ns>/<id>), its log.json the runtime's log.
//   - podman's conmon: github.com/containers/conmon src/runtime_args.c, configure_runtime_args:
//     RUNTIME [--systemd-cgroup] [runtime args…] create --bundle B --pid-file P [--no-pivot]
//     [--no-new-keyring] [runtime opts…] [--console-socket S] CID; and for exec: RUNTIME [runtime
//     args…] exec --pid-file P --process SPEC --detach [runtime opts…] [--console-socket S] CID.
//     podman passes --log-format=json and --log through runtime args for runtimes that take JSON.
//   - crun's own forms: `crun [--cgroup-manager=systemd] create [-f|--config FILE] [-b|--bundle B]`.
const (
	bundle = "/run/containerd/io.containerd.runtime.v2.task/moby/3f2a"
	id     = "3f2a"
)

func TestParse(t *testing.T) {
	for _, c := range []struct {
		name string
		line string
		want Invocation
		err  string
	}{
		{"containerd shim create (docker, systemd cgroups, a terminal)",
			"--root /var/run/docker/runtime-runc/moby --log " + bundle + "/log.json --log-format json --systemd-cgroup create --bundle " + bundle + " --pid-file " + bundle + "/init.pid --console-socket /tmp/pty1234/pty.sock " + id,
			Invocation{Action: "create", Bundle: bundle, ID: id, Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim create, no terminal, rootless flag",
			"--root /run/user/1000/runc/moby --log " + bundle + "/log.json --log-format json --rootless=true create --bundle " + bundle + " --pid-file " + bundle + "/init.pid --no-pivot " + id,
			Invocation{Action: "create", Bundle: bundle, ID: id, Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim create with debug and preserved fds",
			"--root /var/run/docker/runtime-runc/moby --debug --log " + bundle + "/log.json --log-format json create --bundle " + bundle + " --pid-file " + bundle + "/init.pid --no-new-keyring --preserve-fds 2 " + id,
			Invocation{Action: "create", Bundle: bundle, ID: id, Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim exec",
			"--root /var/run/docker/runtime-runc/moby --log " + bundle + "/log.json --log-format json exec --process /tmp/runc-process123 --console-socket /tmp/pty9/pty.sock --detach --pid-file " + bundle + "/9f.pid " + id,
			Invocation{Action: "exec", Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim start", "--root /var/run/docker/runtime-runc/moby --log " + bundle + "/log.json --log-format json start " + id,
			Invocation{Action: "start", Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim delete", "--root /var/run/docker/runtime-runc/moby --log " + bundle + "/log.json --log-format json delete --force " + id,
			Invocation{Action: "delete", Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim kill", "--root /var/run/docker/runtime-runc/moby --log " + bundle + "/log.json --log-format json kill --all " + id + " 9",
			Invocation{Action: "kill", Log: bundle + "/log.json", LogFormat: "json"}, ""},
		{"containerd shim state", "--root /var/run/docker/runtime-runc/moby state " + id, Invocation{Action: "state"}, ""},
		{"conmon create (systemd, json log through runtime args, a terminal)",
			"--systemd-cgroup --log-format=json --log /var/lib/containers/storage/overlay-containers/c1/userdata/oci-log create --bundle /var/lib/containers/storage/overlay-containers/c1/userdata --pid-file /run/containers/storage/overlay-containers/c1/userdata/pidfile --console-socket /run/libpod/socket/c1/attach c1",
			Invocation{Action: "create", Bundle: "/var/lib/containers/storage/overlay-containers/c1/userdata", ID: "c1",
				Log: "/var/lib/containers/storage/overlay-containers/c1/userdata/oci-log", LogFormat: "json"}, ""},
		{"conmon create, no-pivot and keyring",
			"create --bundle /b --pid-file /p --no-pivot --no-new-keyring c1", Invocation{Action: "create", Bundle: "/b", ID: "c1"}, ""},
		{"conmon exec", "exec --pid-file /run/exec.pid --process /run/libpod/exec_pid_c1 --detach --console-socket /run/s c1", Invocation{Action: "exec"}, ""},
		{"crun create, short flags and its own config name", "--cgroup-manager=systemd create -f other.json -b /b c1",
			Invocation{Action: "create", Bundle: "/b", Config: "other.json", ID: "c1"}, ""},
		{"--flag=value forms", "--root=/r --log=/l --log-format=text create --bundle=/b --pid-file=/p c1",
			Invocation{Action: "create", Bundle: "/b", ID: "c1", Log: "/l", LogFormat: "text"}, ""},
		{"run, detached", "--root /r run -d --bundle /b c1", Invocation{Action: "run", Bundle: "/b", ID: "c1"}, ""},
		{"no bundle: the current folder", "create c1", Invocation{Action: "create", ID: "c1"}, ""},
		{"--version", "--version", Invocation{}, ""},
		{"features", "features", Invocation{Action: "features"}, ""},
		{"an unknown action passes", "--root /r frobnicate c1", Invocation{Action: "frobnicate"}, ""},
		{"an unknown value flag that hides a create", "--weird value create --bundle /b c1", Invocation{}, "can't tell the action"},
		{"create without an id", "create --bundle /b", Invocation{}, "without a container id"},
		{"a global flag without its value", "--root", Invocation{}, "has no value"},
		{"bundle without its value", "create --bundle", Invocation{}, "has no value"},
	} {
		got, err := Parse(strings.Fields(c.line))
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: error %v, want %q", c.name, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}
