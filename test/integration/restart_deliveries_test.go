package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// A secret taken away from a silo while kevasod was down must go from the running silo when the
// agent is back. The restarted agent remembers nothing of what it wrote before; it skipped a silo
// that receives nothing now, and the revoked value stayed in its /run until its next stop.
func TestSecretRevokedWhileTheAgentWasDownGoesAfterItsRestart(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("tls-key", nil, "-----BEGIN KEY-----")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "tls-key", Key: "token", Deliver: v1.DeliverFile, Path: "/run/secrets/tls.pem"}}})); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(t.TempDir(), "mounts")
	_ = os.WriteFile(mounts, []byte("/dev/vda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n"), 0o644)
	root := t.TempDir() // the one silo's root, kept across both agents (the VM keeps running)
	rt := fake.New()
	rt.Program = func(ctx context.Context, id kri.ID, req kri.ExecRequest) int {
		cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
		cmd.Env = append(os.Environ(), "KEVASO_TEST_ROOT="+root, "KEVASO_TEST_MOUNTS="+mounts)
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
	run := func(ctx context.Context) {
		a := &agent.Agent{Client: c.host(t, "hv1"), HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
		a.Run(ctx)
	}
	s := silo("one", "web3")
	s.Spec.Grants = []string{"app"}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "/run/secrets/tls.pem")
	waitFor := func(ctx context.Context, what string, ok func() bool) {
		t.Helper()
		for !ok() {
			select {
			case <-ctx.Done():
				t.Fatalf("waiting for %s", what)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	first, stop := context.WithTimeout(c.ctx, 20*time.Second)
	done := make(chan struct{})
	go func() { run(first); close(done) }()
	waitFor(first, "the secret", func() bool {
		var cur v1.Silo
		_ = c.admin.Get(c.ctx, "Silo", "web3", "one", &cur)
		b, _ := os.ReadFile(file)
		return string(b) == "-----BEGIN KEY-----" && meta.IsTrue(cur.Status.Conditions, "SecretsDelivered")
	})
	stop() // kevasod stops; the silo keeps running
	<-done

	// While it's down, the silo loses the grant.
	var cur v1.Silo
	if err := c.admin.Get(c.ctx, "Silo", "web3", "one", &cur); err != nil {
		t.Fatal(err)
	}
	cur.Spec.Grants = nil
	if err := c.admin.Update(c.ctx, &cur); err != nil {
		t.Fatal(err)
	}
	second, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	go run(second)
	waitFor(second, "the revoked secret to go", func() bool { _, err := os.Stat(file); return errors.Is(err, os.ErrNotExist) })
}
