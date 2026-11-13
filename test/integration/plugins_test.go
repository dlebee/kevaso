package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/kvoconfig"
	"kevaso.com/core/internal/kvoplugin"
	"kevaso.com/core/internal/kvoplugin/plugintest"
)

// goBuild builds a package of this module into dir, for this machine.
func goBuild(t *testing.T, dir, out, pkg string, ldflags ...string) string {
	t.Helper()
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("needs the go command")
	}
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	out = filepath.Join(dir, out)
	args := []string{"build", "-o", out}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags", strings.Join(ldflags, " "))
	}
	cmd := exec.Command(gobin, append(args, pkg)...)
	cmd.Dir = filepath.Join("..", "..")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return out
}

// kvo plugins end to end (design §10, ADR 0008): a signed index served over HTTP, the example
// plugin installed for this OS, run through kvo against a real API server with bob's kvo login
// session (his RBAC, a short-lived token, never his refresh token), upgraded, and removed.
func TestKvoPlugins(t *testing.T) {
	c := newCluster(t)
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.yaml")
	t.Setenv("KVO_CONFIG", cfgPath)
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")
	t.Setenv("KVO_TOKEN", "")
	t.Setenv("KVO_PLUGINS_DIR", filepath.Join(home, "plugins"))
	for _, n := range []string{"payments", "other"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	key, csr, _ := clientKeyCSR(t)
	cert, ca, err := c.admin.SignUserCSR(c.ctx, "david", csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := kvoconfig.AddContext(cfgPath, "admin", c.url, ca, cert, key); err != nil {
		t.Fatal(err)
	}
	ok := func(args ...string) string {
		t.Helper()
		out, errs, code := run(c.ctx, kvoCmd, "", args...)
		if code != 0 {
			t.Fatalf("kvo %v: exit %d\n%s%s", args, code, out, errs)
		}
		return out
	}
	invite, _, _ := run(c.ctx, kvoadmCmd, "", "users", "invite", "bob", "--namespace", "payments")
	login := regexp.MustCompile(`kvo login (\S+) --ca (sha256:[0-9a-f]{64})`).FindStringSubmatch(invite)
	code := regexp.MustCompile(`invite code: (kvi_\S+)`).FindStringSubmatch(invite)
	if login == nil || code == nil {
		t.Fatalf("invite: %s", invite)
	}
	saved := kvo.Browser
	kvo.Browser = browser(t, code[1])
	defer func() { kvo.Browser = saved }()
	ok("login", login[1], "--ca", login[2], "--context", "bob")
	ok("ns", "payments")

	// The plugins, built for this machine: the example, twice, and (Unix) a probe that reports
	// what a plugin is given.
	bin := t.TempDir()
	saveExe := kvo.Executable
	kvoBin := goBuild(t, bin, "kvo", "./cmd/kvo")
	kvo.Executable = func() (string, error) { return kvoBin, nil }
	defer func() { kvo.Executable = saveExe }()
	v1 := goBuild(t, bin, "kvo-whoami-1", "./examples/kvo-plugin", "-X main.version=v0.1.0")
	v2 := goBuild(t, bin, "kvo-whoami-2", "./examples/kvo-plugin", "-X main.version=v0.2.0")
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	pub := plugintest.New(t, "kevaso")
	host := kvoplugin.Host()
	pub.Add("whoami", "v0.1.0", host, kvoplugin.KindBinary, "", read(v1))
	other := kvoplugin.Platform{OS: "linux", Arch: "amd64"}
	if host == other {
		other = kvoplugin.Platform{OS: "darwin", Arch: "arm64"}
	}
	pub.Add("elsewhere", "v1.0.0", other, kvoplugin.KindBinary, "", []byte("not for this machine"))
	probe := filepath.Join(home, "probe")
	if runtime.GOOS != "windows" {
		script := "#!/bin/sh\nenv > " + probe + ".env\necho \"$0 $*\" > " + probe + ".args\n\"$KVO_PLUGIN_KVO\" plugin token > " + probe + ".token\n"
		pub.Add("probe", "v1.0.0", host, kvoplugin.KindBinary, "", []byte(script))
	}
	pub.Publish()
	t.Setenv("KVO_PLUGIN_INDEX", pub.URL())
	t.Setenv("KVO_PLUGIN_INDEX_KEY", pub.PublicKey())

	if out := ok("plugin", "search"); !strings.Contains(out, "whoami") || !strings.Contains(out, "no build for "+host.String()) {
		t.Fatalf("search:\n%s", out)
	}
	if _, errs, code := run(c.ctx, kvoCmd, "", "plugin", "install", "elsewhere"); code == 0 || !strings.Contains(errs, "no build for "+host.String()) {
		t.Fatalf("elsewhere: %d %s", code, errs)
	}
	if out := ok("plugin", "install", "whoami"); !strings.Contains(out, "installed whoami v0.1.0") || !strings.Contains(out, "kvo whoami") {
		t.Fatalf("install: %s", out)
	}
	out := ok("whoami")
	for _, want := range []string{"user bob", "context:   bob", "server:    " + c.url, "namespace: payments", "token:     short-lived",
		"list       yes    yes", "exec into  yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("whoami: missing %q in\n%s", want, out)
		}
	}
	// Bob's RBAC and nothing more.
	if out := ok("whoami", "-n", "other"); !strings.Contains(out, "list       no     no") {
		t.Errorf("whoami -n other:\n%s", out)
	}
	if out, _, code := run(c.ctx, kvoCmd, "", "whoami", "--bogus"); code != 1 || out != "" {
		t.Errorf("a plugin's exit code: %d", code)
	}

	// The hand-off: a short-lived access token on request, the refresh token never.
	if runtime.GOOS != "windows" {
		ok("plugin", "install", "probe")
		ok("probe", "--flag", "x")
		var saved struct{ RefreshToken string }
		if err := json.Unmarshal(read(filepath.Join(home, "tokens", "bob")), &saved); err != nil || saved.RefreshToken == "" {
			t.Fatalf("bob's saved session: %v", err)
		}
		env, args := string(read(probe+".env")), string(read(probe+".args"))
		if strings.Contains(env, saved.RefreshToken) || strings.Contains(args, saved.RefreshToken) {
			t.Fatal("the refresh token reached the plugin")
		}
		for _, want := range []string{"KVO_PLUGIN_CONTEXT=bob", "KVO_PLUGIN_SERVER=" + c.url, "KVO_PLUGIN_NAMESPACE=payments", "KVO_PLUGIN_CA_FILE=" + filepath.Join(home, "clusters", "bob", "ca.crt")} {
			if !strings.Contains(env, want+"\n") {
				t.Errorf("plugin env: missing %s", want)
			}
		}
		if !strings.HasSuffix(strings.TrimSpace(args), "kvo-probe --flag x") {
			t.Errorf("args: %q", args)
		}
		var tok kvoplugin.Token
		if err := json.Unmarshal(read(probe+".token"), &tok); err != nil || tok.Token == "" || tok.Token == saved.RefreshToken {
			t.Fatalf("token: %+v %v", tok, err)
		}
		if left := time.Until(tok.ExpiresAt); left <= 0 || left > time.Hour {
			t.Errorf("the token isn't short-lived: %s left", left)
		}
		// Switching context meanwhile doesn't move a running plugin's token: it names its own.
		ok("ctx", "admin")
		t.Setenv(kvoplugin.EnvContext, "bob")
		if out := ok("plugin", "token"); !strings.Contains(out, `"token":"`) {
			t.Errorf("token for bob from another current context: %s", out)
		}
		_ = os.Unsetenv(kvoplugin.EnvContext)
		ok("ctx", "bob")
		ok("plugin", "remove", "probe")
	}

	// A new release: upgrade moves to it.
	pub.Add("whoami", "v0.2.0", host, kvoplugin.KindBinary, "", read(v2))
	pub.Publish()
	if out := ok("whoami", "--version"); out != "v0.1.0\n" {
		t.Fatalf("before upgrade: %q", out)
	}
	if out := ok("plugin", "upgrade"); !strings.Contains(out, "upgraded whoami v0.1.0 → v0.2.0") {
		t.Fatalf("upgrade: %s", out)
	}
	if out := ok("whoami", "--version"); out != "v0.2.0\n" {
		t.Fatalf("after upgrade: %q", out)
	}
	if out := ok("plugin", "list"); !strings.Contains(out, "whoami") || !strings.Contains(out, "v0.2.0") {
		t.Fatalf("list: %s", out)
	}
	ok("plugin", "remove", "whoami")
	if _, errs, code := run(c.ctx, kvoCmd, "", "whoami"); code == 0 || !strings.Contains(errs, "unknown command") {
		t.Fatalf("after remove: %d %s", code, errs)
	}
}
