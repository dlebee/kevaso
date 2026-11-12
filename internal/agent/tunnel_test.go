package agent_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// exec retries while the agent's tunnel is still connecting.
func (e *env) exec(t *testing.T, name, stdin string, cmd ...string) (string, string, int, error) {
	t.Helper()
	for {
		var out, errb bytes.Buffer
		code, err := e.c.Exec(e.ctx, "dev", name, cmd, strings.NewReader(stdin), &out, &errb)
		var ce *client.Error
		if err != nil && asErr(err, &ce) && ce.Reason == "HostNotConnected" && e.ctx.Err() == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return out.String(), errb.String(), code, err
	}
}

func asErr(err error, target **client.Error) bool { return errors.As(err, target) }

func TestExecRunsInTheSiloThroughTheTunnel(t *testing.T) {
	e := setup(t)
	e.rt.Handler = func(id kri.ID, cmd []string, stdin []byte) (string, int) {
		if cmd[0] == "cat" {
			return "in " + id.Name + ": " + string(stdin), 0
		}
		if strings.Join(cmd, " ") == "sh -c exit 3" {
			return "bye", 3
		}
		return "", 0
	}
	e.place(t, "web", "hv1", nil)
	e.wait(t, "web", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })

	out, _, code, err := e.exec(t, "web", "hello from stdin", "cat")
	if err != nil || code != 0 || out != "in web: hello from stdin" {
		t.Fatalf("cat: %q, %d, %v", out, code, err)
	}
	out, _, code, err = e.exec(t, "web", "", "sh", "-c", "exit 3")
	if err != nil || code != 3 || out != "bye" {
		t.Fatalf("exit 3: %q, %d, %v", out, code, err)
	}
	// Big output crosses many frames.
	big := strings.Repeat("x", 300<<10)
	e.rt.Handler = func(kri.ID, []string, []byte) (string, int) { return big, 0 }
	if out, _, _, err := e.exec(t, "web", "", "big"); err != nil || out != big {
		t.Fatalf("big output: %d bytes, %v", len(out), err)
	}
}

func TestExecToAHostWithoutAnAgent(t *testing.T) {
	e := setup(t)
	e.place(t, "far", "hv2", nil)
	_, err := e.c.Exec(e.ctx, "dev", "far", []string{"true"}, nil, nil, nil)
	var ce *client.Error
	if !asErr(err, &ce) || ce.Reason != "HostNotConnected" {
		t.Fatalf("want HostNotConnected, got %v", err)
	}
	_, err = e.c.Exec(e.ctx, "dev", "nope", []string{"true"}, nil, nil, nil)
	if !asErr(err, &ce) || ce.Code != 404 {
		t.Fatalf("want 404 for a missing silo, got %v", err)
	}
}

func TestExecIntoASiloTheRuntimeLacks(t *testing.T) {
	e := setup(t)
	e.place(t, "ghost", "hv1", nil)
	e.wait(t, "ghost", func(s *v1.Silo) bool { return s.Status.Phase == "Running" })
	_ = e.rt.Delete(e.ctx, kri.ID{Namespace: "dev", Name: "ghost", UID: mustUID(t, e, "ghost")})
	_, _, _, err := e.exec(t, "ghost", "", "true")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want the runtime's not-found error, got %v", err)
	}
}

func mustUID(t *testing.T, e *env, name string) string {
	var s v1.Silo
	if err := e.c.Get(e.ctx, "Silo", "dev", name, &s); err != nil {
		t.Fatal(err)
	}
	return s.UID
}
