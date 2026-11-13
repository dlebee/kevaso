package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// File and env secrets written by the host (design §8.2, ADR 0009), end to end in one process: the
// real agent, on a host's own credentials, writes them into its silos through the runtime's exec
// (here: the real sh, in a folder per silo standing in for its root, /run a tmpfs), rewrites them in
// every silo when the one secret rotates, and removes them when the grant goes. Nothing runs in
// the silo but sh.
func TestHostWritesSecrets(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	for _, s := range []*v1.Secret{secretObj("tls-key", nil, "-----BEGIN KEY-----"), secretObj("legacy-token", nil, "tok'en")} {
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "tls-key", Deliver: v1.DeliverFile, Path: "/run/secrets/tls.pem"},
		{Name: "legacy-token", Deliver: v1.DeliverEnv},
	}})); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(t.TempDir(), "mounts")
	_ = os.WriteFile(mounts, []byte("/dev/vda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n"), 0o644)
	var mu sync.Mutex
	roots := map[string]string{}
	rootOf := func(name string) string {
		mu.Lock()
		defer mu.Unlock()
		if roots[name] == "" {
			roots[name] = t.TempDir()
		}
		return roots[name]
	}
	rt := fake.New()
	rt.Program = func(ctx context.Context, id kri.ID, req kri.ExecRequest) int {
		cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
		cmd.Env = append(os.Environ(), "KEVASO_TEST_ROOT="+rootOf(id.Name), "KEVASO_TEST_MOUNTS="+mounts)
		var in []byte
		if req.Stdin != nil {
			in, _ = io.ReadAll(req.Stdin)
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(in), req.Stdout, req.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 127
		}
		return 0
	}
	ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
	defer cancel()
	a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	for _, name := range []string{"one", "two"} {
		s := silo(name, "web3")
		s.Spec.Grants = []string{"app"}
		if err := c.admin.Create(c.ctx, s); err != nil {
			t.Fatal(err)
		}
		s.Status.Host = "hv1"
		if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name, p string) string {
		b, _ := os.ReadFile(filepath.Join(rootOf(name), p))
		return string(b)
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for !ok() {
			select {
			case <-ctx.Done():
				t.Fatalf("waiting for %s", what)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	for _, name := range []string{"one", "two"} {
		waitFor(name+"'s secrets", func() bool {
			return read(name, "/run/secrets/tls.pem") == "-----BEGIN KEY-----" && read(name, agent.EnvFile) == "LEGACY_TOKEN='tok'\\''en'\n"
		})
		fi, _ := os.Stat(filepath.Join(rootOf(name), "/run/secrets/tls.pem"))
		if fi.Mode().Perm() != 0o400 {
			t.Fatalf("%s: mode %v", name, fi.Mode().Perm())
		}
		var s v1.Silo
		_ = c.admin.Get(c.ctx, "Silo", "web3", name, &s)
		waitFor(name+"'s condition", func() bool {
			_ = c.admin.Get(c.ctx, "Silo", "web3", name, &s)
			for _, cd := range s.Status.Conditions {
				if cd.Type == "SecretsDelivered" && cd.Status == meta.ConditionTrue && strings.Contains(cd.Message, "1 files, 1 environment variables") {
					return true
				}
			}
			return false
		})
	}

	// One secret rotated: rewritten in every silo that has it.
	var tls v1.Secret
	_ = c.admin.Get(c.ctx, "Secret", "web3", "tls-key", &tls)
	tls.Spec.Value = []byte("-----BEGIN KEY v2-----")
	if err := c.admin.Update(c.ctx, &tls); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		waitFor(name+" rotated", func() bool { return read(name, "/run/secrets/tls.pem") == "-----BEGIN KEY v2-----" })
	}
	// The env delivery leaves the grant: its file and profile go from every silo.
	var g v1.Grant
	_ = c.admin.Get(c.ctx, "Grant", "web3", "app", &g)
	g.Spec.Secrets = g.Spec.Secrets[:1]
	if err := c.admin.Update(c.ctx, &g); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		waitFor(name+"'s env secret removed", func() bool {
			_, e1 := os.Stat(filepath.Join(rootOf(name), agent.EnvFile))
			_, e2 := os.Stat(filepath.Join(rootOf(name), agent.EnvProfile))
			return os.IsNotExist(e1) && os.IsNotExist(e2) && read(name, "/run/secrets/tls.pem") != ""
		})
	}
}
