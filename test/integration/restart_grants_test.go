package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// slowGrants delays the agent's list of Grants (a restarted kevasod whose Grant informer is
// behind its Silo informer).
type slowGrants struct{ next http.RoundTripper }

func (s slowGrants) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/grants") && r.URL.Query().Get("watch") == "" {
		time.Sleep(700 * time.Millisecond)
	}
	return s.next.RoundTrip(r)
}

// A silo must never start (or run its init steps) before the agent knows its grants: with the
// Grant cache still empty, the agent saw nothing to deliver, ran the init steps without the
// silo's secrets (a firstBoot step stays done that way), and a container was made afresh without
// its secret mounts and variables.
func TestASiloWaitsForItsGrantsBeforeItsInitSteps(t *testing.T) {
	c := newCluster(t)
	_ = c.admin.Create(c.ctx, ns("web3"))
	if err := c.admin.Create(c.ctx, secretObj("tls-key", nil, "-----BEGIN KEY-----")); err != nil {
		t.Fatal(err)
	}
	if err := c.admin.Create(c.ctx, grantObj("app", v1.GrantSpec{Secrets: []v1.GrantSecret{
		{Name: "tls-key", Deliver: v1.DeliverFile, Path: "/run/secrets/tls.pem"}}})); err != nil {
		t.Fatal(err)
	}
	mounts := filepath.Join(t.TempDir(), "mounts")
	_ = os.WriteFile(mounts, []byte("/dev/vda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n"), 0o644)
	root := t.TempDir()
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
	hc := c.host(t, "hv1")
	tr := http.DefaultTransport
	if hc.HTTP != nil && hc.HTTP.Transport != nil {
		tr = hc.HTTP.Transport
	}
	hc.HTTP = &http.Client{Transport: slowGrants{tr}}
	s := silo("one", "web3")
	s.Spec.Grants = []string{"app"}
	// The step needs the secret: it fails without it.
	s.Spec.Init = &v1.Init{Steps: []v1.InitStep{{Name: "needs-key", Run: `test -f "$KEVASO_TEST_ROOT/run/secrets/tls.pem"`}}}
	if err := c.admin.Create(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host = "hv1"
	if err := c.admin.UpdateStatus(c.ctx, s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()
	a := &agent.Agent{Client: hc, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	defer runAgent(ctx, a)()
	for {
		var cur v1.Silo
		_ = c.admin.Get(c.ctx, "Silo", "web3", "one", &cur)
		if meta.IsTrue(cur.Status.Conditions, "InitFailed") {
			t.Fatalf("its init step ran before its secret was there: %+v", cur.Status.Init)
		}
		if meta.IsTrue(cur.Status.Conditions, "Ready") {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("never ready: %+v", cur.Status)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
