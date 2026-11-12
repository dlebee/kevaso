package integration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"kevaso.com/core/internal/cli/kvo"
	"kevaso.com/core/internal/cli/kvoadm"
	"kevaso.com/core/internal/kvoconfig"
)

func run(ctx context.Context, f func(context.Context, []string, *strings.Reader, *bytes.Buffer, *bytes.Buffer) int, stdin string, args ...string) (string, string, int) {
	var o, e bytes.Buffer
	code := f(ctx, args, strings.NewReader(stdin), &o, &e)
	return o.String(), e.String(), code
}

func kvoCmd(ctx context.Context, a []string, in *strings.Reader, o, e *bytes.Buffer) int {
	return kvo.Run(ctx, a, in, o, e)
}
func kvoadmCmd(ctx context.Context, a []string, in *strings.Reader, o, e *bytes.Buffer) int {
	return kvoadm.Run(ctx, a, in, o, e)
}

// The M4 story with the real commands: the admin invites bob into a namespace, bob signs in with
// kvo login, works there, and nowhere else.
func TestKvoLoginAndRBACFromTheCLI(t *testing.T) {
	c := newCluster(t)
	home := t.TempDir()
	cfgPath := filepath.Join(home, "config.yaml")
	t.Setenv("KVO_CONFIG", cfgPath)
	t.Setenv("KVO_TOKEN_STORE", "file")
	t.Setenv("KVO_SERVER", "")
	for _, n := range []string{"payments", "other"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	_ = c.admin.Create(c.ctx, silo("ledger", "other"))
	// The admin's context, like kvoadm init writes (a cluster-admin certificate).
	key, csr, _ := clientKeyCSR(t)
	cert, ca, err := c.admin.SignUserCSR(c.ctx, "david", csr)
	if err != nil {
		t.Fatal(err)
	}
	if err := kvoconfig.AddContext(cfgPath, "admin", c.url, ca, cert, key); err != nil {
		t.Fatal(err)
	}
	ok := func(f func(context.Context, []string, *strings.Reader, *bytes.Buffer, *bytes.Buffer) int, stdin string, args ...string) string {
		t.Helper()
		out, errs, code := run(c.ctx, f, stdin, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, out, errs)
		}
		return out
	}

	out := ok(kvoadmCmd, "", "users", "invite", "bob", "--namespace", "payments")
	login := regexp.MustCompile(`kvo login (\S+) --ca (sha256:[0-9a-f]{64})`).FindStringSubmatch(out)
	code := regexp.MustCompile(`invite code: (kvi_\S+)`).FindStringSubmatch(out)
	if login == nil || code == nil || !strings.Contains(out, "bob is editor in namespace payments") {
		t.Fatalf("invite output:\n%s", out)
	}

	saved := kvo.Browser
	kvo.Browser = browser(t, code[1])
	defer func() { kvo.Browser = saved }()
	if out := ok(kvoCmd, "", "login", login[1], "--ca", login[2], "--context", "bob"); !strings.Contains(out, "signed in to "+c.url+" as bob") {
		t.Fatalf("login: %s", out)
	}
	if out := ok(kvoCmd, "", "auth", "whoami"); !strings.HasPrefix(out, "user bob") {
		t.Fatalf("whoami: %s", out)
	}
	ok(kvoCmd, "", "ns", "payments")
	ok(kvoCmd, `{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"api"},"spec":{"runtime":"cloud-hypervisor","image":"ubuntu-24.04","resources":{"cpu":1,"memory":"1Gi"}}}`, "apply", "-f", "-")
	if out := ok(kvoCmd, "", "get", "silos"); !strings.Contains(out, "api") {
		t.Fatalf("get silos (default ns from kvo ns): %s", out)
	}
	if out := ok(kvoCmd, "", "get", "ns"); !strings.Contains(out, "payments") || strings.Contains(out, "other") {
		t.Fatalf("bob's namespaces: %s", out)
	}
	for _, args := range [][]string{{"get", "silos", "-n", "other"}, {"get", "silo", "ledger", "-n", "other"}, {"get", "hosts"}, {"get", "silos", "-A"}} {
		if _, errs, code := run(c.ctx, kvoCmd, "", args...); code == 0 || !strings.Contains(errs, "Forbidden") {
			t.Errorf("bob %v: exit %d %s", args, code, errs)
		}
	}
	if out, _, code := run(c.ctx, kvoCmd, "", "auth", "can-i", "create", "silos/exec"); code != 0 || !strings.HasPrefix(out, "yes") {
		t.Errorf("can-i create silos/exec: %d %s", code, out)
	}
	if out, _, code := run(c.ctx, kvoCmd, "", "auth", "can-i", "delete", "silo/ledger", "-n", "other"); code != 1 || !strings.HasPrefix(out, "no") {
		t.Errorf("can-i delete silo/ledger -n other: %d %s", code, out)
	}
	if out := ok(kvoCmd, "", "ctx"); !strings.Contains(out, "*         bob") || !strings.Contains(out, "admin") {
		t.Fatalf("ctx:\n%s", out)
	}

	// Bob can't manage users; the admin lists and disables him.
	if _, errs, code := run(c.ctx, kvoadmCmd, "", "users", "invite", "eve"); code == 0 || !strings.Contains(errs, "Forbidden") {
		t.Errorf("bob inviting: %d %s", code, errs)
	}
	if out := ok(kvoadmCmd, "", "users", "list", "--context", "admin"); !strings.Contains(out, "bob") || !strings.Contains(out, "active") {
		t.Fatalf("users list:\n%s", out)
	}
	ok(kvoadmCmd, "", "users", "disable", "bob", "--context", "admin")
	if _, errs, code := run(c.ctx, kvoCmd, "", "get", "silos"); code == 0 || !strings.Contains(errs, "Unauthorized") {
		t.Errorf("bob after disable: %d %s", code, errs)
	}
	ok(kvoCmd, "", "logout")
	if _, errs, code := run(c.ctx, kvoCmd, "", "get", "silos"); code == 0 || !strings.Contains(errs, "not signed in") {
		t.Errorf("after logout: %d %s", code, errs)
	}
}

// A service account for CI: a token from kvo create token, used through $KVO_TOKEN, limited by
// RBAC, and dead once the account is deleted (even if it's re-created).
func TestServiceAccountTokens(t *testing.T) {
	c := newCluster(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("KVO_CONFIG", cfgPath)
	t.Setenv("KVO_SERVER", "")
	t.Setenv("KVO_TOKEN", "")
	for _, n := range []string{"payments", "other"} {
		_ = c.admin.Create(c.ctx, ns(n))
	}
	key, csr, _ := clientKeyCSR(t)
	cert, ca, _ := c.admin.SignUserCSR(c.ctx, "david", csr)
	_ = kvoconfig.AddContext(cfgPath, "admin", c.url, ca, cert, key)
	ok := func(stdin string, args ...string) string {
		t.Helper()
		out, errs, code := run(c.ctx, kvoCmd, stdin, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", args, code, out, errs)
		}
		return out
	}
	ok(`apiVersion: kevaso/v1
kind: ServiceAccount
metadata: { name: deployer, namespace: payments }
---
apiVersion: kevaso/v1
kind: RoleBinding
metadata: { name: deployer, namespace: payments }
roleRef: { kind: ClusterRole, name: editor }
subjects: [{ kind: ServiceAccount, name: deployer }]
`, "apply", "-f", "-")
	if _, errs, code := run(c.ctx, kvoCmd, "", "create", "token", "nobody", "-n", "payments"); code == 0 || !strings.Contains(errs, "NotFound") {
		t.Errorf("token for a missing account: %d %s", code, errs)
	}
	tok := strings.TrimSpace(ok("", "create", "token", "deployer", "-n", "payments", "--duration", "10m"))
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("token %q", tok)
	}
	if _, errs, code := run(c.ctx, kvoCmd, "", "create", "token", "deployer", "-n", "payments", "--duration", "9999h"); code == 0 || !strings.Contains(errs, "90 days") {
		t.Errorf("too long: %d %s", code, errs)
	}

	t.Setenv("KVO_TOKEN", tok)
	if out := ok("", "auth", "whoami"); !strings.HasPrefix(out, "serviceaccount system:serviceaccount:payments:deployer") {
		t.Fatalf("whoami: %s", out)
	}
	ok(`{"apiVersion":"kevaso/v1","kind":"Silo","metadata":{"name":"api","namespace":"payments"},"spec":{"runtime":"cloud-hypervisor","image":"ubuntu-24.04","resources":{"cpu":1,"memory":"1Gi"}}}`, "apply", "-f", "-")
	if _, errs, code := run(c.ctx, kvoCmd, "", "get", "silos", "-n", "other"); code == 0 || !strings.Contains(errs, "Forbidden") {
		t.Errorf("SA in another namespace: %d %s", code, errs)
	}
	// editor includes serviceaccounts/token (as in Kubernetes), only in its namespace.
	if _, errs, code := run(c.ctx, kvoCmd, "", "create", "token", "deployer", "-n", "payments"); code != 0 {
		t.Errorf("editor minting a token in its namespace: %s", errs)
	}

	// With --server and KVO_CA_FILE instead of a context.
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caFile, c.ca, 0o644)
	t.Setenv("KVO_CA_FILE", caFile)
	if out := ok("", "get", "silos", "-n", "payments", "--server", c.url); !strings.Contains(out, "api") {
		t.Fatalf("with --server: %s", out)
	}
	t.Setenv("KVO_CA_FILE", "")

	// Deleting the account ends the token, and re-creating it doesn't bring it back.
	t.Setenv("KVO_TOKEN", "")
	ok("", "delete", "serviceaccount", "deployer", "-n", "payments")
	ok(`{"apiVersion":"kevaso/v1","kind":"ServiceAccount","metadata":{"name":"deployer","namespace":"payments"}}`, "apply", "-f", "-")
	t.Setenv("KVO_TOKEN", tok)
	if _, errs, code := run(c.ctx, kvoCmd, "", "get", "silos", "-n", "payments"); code == 0 || !strings.Contains(errs, "Unauthorized") {
		t.Errorf("token after the account was deleted: %d %s", code, errs)
	}
}
