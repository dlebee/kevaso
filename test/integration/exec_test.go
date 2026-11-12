package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// `kvo exec` end to end in one process: kvo → API server → the agent's tunnel → the runtime.
func TestKvoExec(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rt := fake.New()
	rt.Handler = func(id kri.ID, cmd []string, stdin []byte) (string, int) {
		if cmd[0] == "false" {
			return "", 1
		}
		return strings.Join(cmd, " ") + " in " + id.Name + " <" + string(stdin) + ">", 0
	}
	a := &agent.Agent{Client: client.New(h.server), HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{}}
	go a.Run(ctx)
	h.ok(manifest, "apply", "-f", "-")
	// What the scheduler would write: the silo is on hv1 (the agent then starts it).
	c := client.New(h.server)
	var s v1.Silo
	if err := c.Get(ctx, "Silo", "demo", "hello", &s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, &s); err != nil {
		t.Fatal(err)
	}

	for {
		out, errs, code := h.kvo(ctx, "piped", "exec", "silo", "hello", "-n", "demo", "--", "echo", "-n", "hi")
		if code != 0 && (strings.Contains(errs, "HostNotConnected") || strings.Contains(errs, "not found") || strings.Contains(errs, "not running")) && ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond) // the agent is still connecting or starting the silo
			continue
		}
		if code != 0 || out != "echo -n hi in hello <piped>" {
			t.Fatalf("exec: exit %d, %q, %q", code, out, errs)
		}
		break
	}
	if _, _, code := h.kvo(ctx, "", "exec", "silo", "hello", "-n", "demo", "--", "false"); code != 1 {
		t.Fatalf("kvo exec false: exit %d, want the command's 1", code)
	}
	for _, bad := range [][]string{{"exec", "silo", "hello"}, {"exec", "host", "hv1", "--", "ls"}, {"exec", "silo", "--", "ls"}} {
		if _, _, code := h.kvo(ctx, "", bad...); code == 0 {
			t.Errorf("kvo %v: want a usage error", bad)
		}
	}
}
