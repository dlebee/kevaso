//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/testbed"
)

// rig is one run's machines and the helpers every M13–M15 test needs: the same loop as the earlier
// tests (create, add with kvoadm, test, tear down), written once. The control plane's API is
// reached on 127.0.0.1:6443, which Lima forwards from the machine that runs it.
type rig struct {
	t        *testing.T
	ctx      context.Context
	d        testbed.Driver
	sshd     testbed.SSHAccess
	run      testbed.RunID
	arch     string
	machines map[string]testbed.Machine
	bin      string // kevasod for linux/arch
}

// newRig creates the machines (in parallel), sets up a kvo of the test's own, and builds kevasod.
// The machines are deleted when the test ends (unless KEVASO_E2E_KEEP is set).
func newRig(t *testing.T, timeout time.Duration, specs map[string]testbed.Spec) *rig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
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
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")

	r := &rig{t: t, ctx: ctx, d: d, sshd: sshd, run: testbed.NewRunID(), arch: arch, machines: map[string]testbed.Machine{}}
	t.Logf("run %s", r.run)
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING the run's machines (limactl list | grep %s)", r.run)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, s := range specs {
			m := testbed.Machine{Name: testbed.MachineName(r.run, s.Role), Run: r.run, Role: s.Role}
			if err := d.Delete(ctx, m); err != nil {
				t.Errorf("teardown %s: %v", m.Name, err)
			}
		}
	})
	var mu sync.Mutex
	var wg sync.WaitGroup
	errs := make(chan error, len(specs))
	for name, s := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := d.Create(ctx, r.run, s)
			if err != nil {
				errs <- fmt.Errorf("create %s: %w", name, err)
				return
			}
			mu.Lock()
			r.machines[name] = m
			mu.Unlock()
		}()
	}
	r.bin = filepath.Join(t.TempDir(), "kevasod")
	build := exec.CommandContext(ctx, "go", "build", "-o", r.bin, "kevaso.com/core/cmd/kevasod")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	out, berr := build.CombinedOutput()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if berr != nil {
		t.Fatalf("build: %v\n%s", berr, out)
	}
	return r
}

// sh runs a script as root on a machine.
func (r *rig) sh(name, cmd string) (string, error) {
	return r.d.Exec(r.ctx, r.machines[name], "sudo", "sh", "-c", cmd)
}

// ip is a machine's address on the run's shared network.
func (r *rig) ip(name string) string {
	r.t.Helper()
	out, err := r.sh(name, `ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1`)
	if err != nil || strings.TrimSpace(out) == "" {
		r.t.Fatalf("%s's address: %q %v", name, out, err)
	}
	return strings.TrimSpace(out)
}

// sshArgs are kvoadm's arguments to reach a machine.
func (r *rig) sshArgs(name string) []string {
	r.t.Helper()
	info, err := r.sshd.SSH(r.ctx, r.machines[name])
	if err != nil {
		r.t.Fatal(err)
	}
	hk, err := r.d.Exec(r.ctx, r.machines[name], "ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		r.t.Fatal(err)
	}
	return []string{info.User + "@" + info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", strings.Fields(hk)[1], "--kevasod", r.bin}
}

type cliFunc func(context.Context, []string, io.Reader, io.Writer, io.Writer) int

// must runs a CLI and fails the test unless it exits 0.
func (r *rig) must(f cliFunc, stdin string, args ...string) string {
	r.t.Helper()
	var o, e bytes.Buffer
	if code := f(r.ctx, args, strings.NewReader(stdin), &o, &e); code != 0 {
		r.t.Fatalf("%v: exit %d\n%s%s", args, code, o.String(), e.String())
	}
	return o.String()
}

// kvo runs kvo and returns its combined output and exit code.
func (r *rig) kvo(stdin string, args ...string) (string, int) {
	return kvoRun(r.ctx, stdin, args...)
}

// in runs a script inside a silo and returns what it printed and its exit code.
func (r *rig) in(ns, silo, script string) (string, int) {
	var o bytes.Buffer
	code := kvo.Run(r.ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", script}, nil, &o, &o)
	return strings.TrimSpace(o.String()), code
}

// upload writes a file into a silo (executable).
func (r *rig) upload(ns, silo, path string, data []byte) {
	r.t.Helper()
	var o bytes.Buffer
	if code := kvo.Run(r.ctx, []string{"exec", "silo", silo, "-n", ns, "--", "sh", "-c", "cat > " + path + " && chmod +x " + path},
		bytes.NewReader(data), &o, &o); code != 0 {
		r.t.Fatalf("upload %s to %s: exit %d %s", path, silo, code, o.String())
	}
}

// silo reads a silo.
func (r *rig) silo(ns, name string) *v1.Silo {
	r.t.Helper()
	var s v1.Silo
	if err := json.Unmarshal([]byte(r.must(kvo.Run, "", "get", "silo", name, "-n", ns, "-o", "json")), &s); err != nil {
		r.t.Fatal(err)
	}
	return &s
}

// journal is the end of kevasod's log on a machine, for failure messages.
func (r *rig) journal(name string, lines int) string {
	j, _ := r.sh(name, fmt.Sprintf("journalctl -u kevasod -n %d --no-pager | grep -v 'retry in' | tail -%d", lines*2, lines))
	return j
}

// waitRunning waits until the named silos are Running, and fails with what it knows otherwise.
func (r *rig) waitRunning(ns string, within time.Duration, logsFrom string, silos ...string) {
	r.t.Helper()
	deadline := time.Now().Add(within)
	for waited := 1; ; waited++ {
		out, code := r.kvo("", "get", "silos", "-n", ns, "-o", "json")
		running, failed := 0, ""
		if code == 0 {
			for _, s := range parseSilos(out) {
				for _, want := range silos {
					if s.Name != want {
						continue
					}
					switch s.Status.Phase {
					case "Running":
						running++
					case "Failed":
						failed = s.Name
					}
				}
			}
		}
		if running == len(silos) {
			table, _ := r.kvo("", "get", "silos", "-n", ns)
			r.t.Logf("silos:\n%s", table)
			return
		}
		if time.Now().After(deadline) || failed != "" {
			table, _ := r.kvo("", "get", "silos", "-n", ns)
			for _, s := range silos {
				desc, _ := r.kvo("", "describe", "silo", s, "-n", ns)
				r.t.Log(desc)
			}
			r.t.Fatalf("silos never all Running (%v):\n%s\nkevasod on %s:\n%s", silos, table, logsFrom, r.journal(logsFrom, 60))
		}
		if waited%12 == 0 {
			table, _ := r.kvo("", "get", "silos", "-n", ns)
			r.t.Logf("still waiting:\n%s", table)
		}
		time.Sleep(10 * time.Second)
	}
}

// eventually polls f every second until it says yes or within passes; it returns whether it did.
func (r *rig) eventually(what string, within time.Duration, f func() (bool, string)) bool {
	r.t.Helper()
	start := time.Now()
	last := ""
	for time.Since(start) < within {
		ok, got := f()
		if ok {
			r.t.Logf("%s: ok after %s", what, time.Since(start).Round(time.Second))
			return true
		}
		last = got
		time.Sleep(time.Second)
	}
	r.t.Errorf("%s: not within %s; last: %s", what, within, last)
	return false
}

// internet makes the stand-in internet on a machine (inetSetup, for these names) and returns its CA.
func (r *rig) internet(machine string, names ...string) string {
	r.t.Helper()
	sans := make([]string, len(names))
	for i, n := range names {
		sans[i] = "DNS:" + n
	}
	setup := strings.ReplaceAll(inetSetup, "DNS:api.allowed.test,DNS:pass.test,DNS:other.blocked.test", strings.Join(sans, ","))
	setup = strings.ReplaceAll(setup, "/CN=api.allowed.test", "/CN="+names[0])
	out, err := r.sh(machine, setup)
	if err != nil {
		r.t.Fatalf("internet: %v\n%s", err, out)
	}
	i := strings.Index(out, "-----BEGIN CERTIFICATE-----")
	if i < 0 {
		r.t.Fatalf("internet: no CA in %q", out)
	}
	return strings.TrimSpace(out[i:])
}

// jsonItems reads kvo get -o json: an array, a list, or (one item) the object itself.
func jsonItems(out string) []json.RawMessage {
	data := []byte(strings.TrimSpace(out))
	var items []json.RawMessage
	if json.Unmarshal(data, &items) == nil {
		return items
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Kind  string            `json:"kind"`
	}
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	if list.Items != nil || strings.HasSuffix(list.Kind, "List") {
		return list.Items
	}
	return []json.RawMessage{data}
}

func parseSilos(out string) []*v1.Silo {
	var silos []*v1.Silo
	for _, raw := range jsonItems(out) {
		var s v1.Silo
		if json.Unmarshal(raw, &s) == nil && s.Name != "" {
			silos = append(silos, &s)
		}
	}
	return silos
}

// expect checks got has want, and logs it.
func expect(t *testing.T, what, got, want string) bool {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("%s: got %q, want %q", what, got, want)
		return false
	}
	t.Logf("%s: ok", what)
	return true
}

// execGo is the go command, building for the machines.
func execGo(r *rig, args ...string) *exec.Cmd {
	c := exec.CommandContext(r.ctx, "go", args...)
	c.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+r.arch, "CGO_ENABLED=0")
	return c
}

// on is the rig reporting to a subtest.
func (r *rig) on(t *testing.T) *rig {
	c := *r
	c.t = t
	return &c
}
