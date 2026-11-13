//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/internal/audit"
	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/testbed"
)

// TestASecondUserOnlySeesTheirNamespace is M4's "done when", on a real machine: kvoadm init, the
// admin invites bob into one namespace, bob signs in with kvo login (browser + invite code, against
// the control plane's own issuer behind its private CA), works there, is refused everywhere else,
// and the host's audit log has it all.
func TestASecondUserOnlySeesTheirNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
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
	t.Setenv("KVO_TOKEN_STORE", "file") // not the developer's real keychain
	t.Setenv("KVO_SERVER", "")
	t.Setenv("KVO_TOKEN", "")

	run := testbed.NewRunID()
	spec := testbed.Spec{Role: "cp", CPUs: 2, Memory: "2GiB", Disk: "10GiB"}
	planned := testbed.Machine{Name: testbed.MachineName(run, spec.Role), Run: run, Role: spec.Role}
	t.Cleanup(func() {
		if os.Getenv("KEVASO_E2E_KEEP") != "" {
			t.Logf("KEEPING %s (limactl delete -f %s)", planned.Name, planned.Name)
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

	type cmd func(context.Context, []string, io.Reader, io.Writer, io.Writer) int
	runCmd := func(f cmd, stdin string, args ...string) (string, string, int) {
		var o, e bytes.Buffer
		code := f(ctx, args, strings.NewReader(stdin), &o, &e)
		return o.String(), e.String(), code
	}
	must := func(f cmd, stdin string, args ...string) string {
		t.Helper()
		o, e, code := runCmd(f, stdin, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, o, e)
		}
		return o
	}
	must(kvoadm.Run, "", "init", info.User+"@"+info.Host, "--ssh-port", strconv.Itoa(info.Port), "--ssh-key", info.KeyFile,
		"--host-key", pin, "--kevasod", bin, "--name", "cp-1", "--cluster", "e2e", "--api-server", "https://127.0.0.1:6443")

	// The admin (kvoadm's certificate context) sets up two namespaces and invites bob into one.
	must(kvo.Run, `
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: payments }
---
apiVersion: kevaso/v1
kind: Namespace
metadata: { name: secret-project }
---
apiVersion: kevaso/v1
kind: Silo
metadata: { name: ledger, namespace: secret-project }
spec: { runtime: cloud-hypervisor, vm: { image: ubuntu-24.04 }, resources: { cpu: 1, memory: 1Gi } }
`, "apply", "-f", "-")
	inv := must(kvoadm.Run, "", "users", "invite", "bob", "--namespace", "payments")
	t.Logf("kvoadm users invite:\n%s", regexp.MustCompile(`kvi_\S+`).ReplaceAllString(inv, "kvi_…"))
	login := regexp.MustCompile(`kvo login (\S+) --ca (sha256:[0-9a-f]{64})`).FindStringSubmatch(inv)
	code := regexp.MustCompile(`invite code: (kvi_\S+)`).FindStringSubmatch(inv)
	if login == nil || code == nil {
		t.Fatalf("invite output:\n%s", inv)
	}

	// Bob signs in: kvo serves the sign-in page on 127.0.0.1 (relayed to the VM over the pinned TLS);
	// this "browser" opens it, pastes the code and submits.
	saved := kvo.Browser
	kvo.Browser = func(authURL string) error { return playBrowser(authURL, code[1]) }
	defer func() { kvo.Browser = saved }()
	if o := must(kvo.Run, "", "login", login[1], "--ca", login[2], "--context", "bob"); !strings.Contains(o, "as bob") {
		t.Fatalf("login: %s", o)
	}
	must(kvo.Run, "", "ns", "payments")
	must(kvo.Run, `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"api"},"spec":{"runtime":"cloud-hypervisor","vm":{"image":"ubuntu-24.04"},"resources":{"cpu":1,"memory":"1Gi"}}}`, "apply", "-f", "-")
	if o := must(kvo.Run, "", "get", "silos"); !strings.Contains(o, "api") {
		t.Fatalf("bob's silos: %s", o)
	}
	if o := must(kvo.Run, "", "get", "ns"); !strings.Contains(o, "payments") || strings.Contains(o, "secret-project") {
		t.Fatalf("bob sees namespaces:\n%s", o)
	}
	for _, args := range [][]string{{"get", "silos", "-n", "secret-project"}, {"get", "silo", "ledger", "-n", "secret-project"}, {"get", "hosts"}, {"get", "silos", "-A"}} {
		if _, e, code := runCmd(kvo.Run, "", args...); code == 0 || !strings.Contains(e, "Forbidden") {
			t.Errorf("bob %v: exit %d %s", args, code, e)
		}
	}
	if _, e, code := runCmd(kvoadm.Run, "", "users", "invite", "eve"); code == 0 || !strings.Contains(e, "Forbidden") {
		t.Errorf("bob inviting: %d %s", code, e)
	}

	// The admin still sees everything; then disables bob, which ends his session at once.
	if o := must(kvo.Run, "", "get", "silos", "-A", "--context", "e2e"); !strings.Contains(o, "ledger") || !strings.Contains(o, "api") {
		t.Fatalf("admin's view:\n%s", o)
	}
	must(kvoadm.Run, "", "users", "disable", "bob", "--context", "e2e")
	if _, e, code := runCmd(kvo.Run, "", "get", "silos"); code == 0 || !strings.Contains(e, "Unauthorized") {
		t.Errorf("bob after disable: %d %s", code, e)
	}

	// The host's audit log.
	log, err := d.Exec(ctx, m, "sudo", "cat", "/var/lib/kevaso/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	var entries []audit.Entry
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	for what, pred := range map[string]func(audit.Entry) bool{
		"bob's sign-in": func(e audit.Entry) bool { return e.Event == "sign-in" && e.User == "bob" && e.Allowed },
		"bob's create": func(e audit.Entry) bool {
			return e.User == "bob" && e.Verb == "create" && e.Resource == "silos" && e.Allowed
		},
		"bob refused":         func(e audit.Entry) bool { return e.User == "bob" && e.Namespace == "secret-project" && !e.Allowed },
		"bob disabled":        func(e audit.Entry) bool { return e.Event == "disable" && e.User == "bob" },
		"the refused session": func(e audit.Entry) bool { return e.Event == "authenticate" && !e.Allowed },
	} {
		if !slices.ContainsFunc(entries, pred) {
			t.Errorf("audit log has no entry for %s", what)
		}
	}
	t.Logf("audit log: %d entries", len(entries))
	if fi, err := d.Exec(ctx, m, "sudo", "stat", "-c", "%a %U", "/var/lib/kevaso/audit.log"); err != nil || strings.TrimSpace(fi) != "600 root" {
		t.Errorf("audit log mode/owner: %q %v", fi, err)
	}
}

// playBrowser does what a person does on the sign-in page.
func playBrowser(authURL, code string) error {
	resp, err := http.Get(authURL)
	if err != nil {
		return err
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(page), "Sign in to Kevaso") {
		return errors.New("no sign-in page")
	}
	u, _ := url.Parse(authURL)
	form := url.Values{"invite": {code}}
	for _, k := range []string{"redirect_uri", "state", "code_challenge", "nonce"} {
		form.Set(k, u.Query().Get(k))
	}
	resp, err = http.PostForm("http://"+u.Host+client.PathLogin, form)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}
