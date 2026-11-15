package agent_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// duringPull is the pulling fake whose pulls after the first run during (a person changing the
// spec back while the registry answers).
type duringPull struct {
	*fake.Runtime
	pulls  atomic.Int32
	during func()
}

func (p *duringPull) Pull(context.Context, kri.ID, string, *kri.RegistryAuth) (string, error) {
	if p.pulls.Add(1) == 2 && p.during != nil {
		p.during()
	}
	return "sha256:" + strings.Repeat("1", 64), nil
}

// Review (check-then-act) claim 1: a reset asked for and taken back while its image is pulled
// must not wipe the disk. The stop and the reset are gated by a conditional write on what is
// stored right before the disk is touched: same generation, and the reset still due.
func TestAResetTakenBackDuringItsPullWipesNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() { cancel(); ts.Close() })
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	rt := &duringPull{Runtime: fake.New()}
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"docker": rt}, Clock: clock.Real{}, Log: t.Logf}
	go a.Run(ctx)
	e := &env{c: c, ctx: ctx}
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "db", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "ghcr.io/acme/db:v1"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	e.wait(t, "db", func(s *v1.Silo) bool { return meta.IsTrue(s.Status.Conditions, "Ready") })
	setReset := func(v string) {
		for {
			var cur v1.Silo
			if err := c.Get(ctx, "Silo", "dev", "db", &cur); err != nil {
				t.Error(err)
				return
			}
			cur.Spec.Reset = v
			err := c.Update(ctx, &cur)
			if err == nil {
				return
			}
			if !client.IsConflict(err) {
				t.Error(err)
				return
			}
		}
	}
	var undone atomic.Bool
	rt.during = func() { setReset(""); undone.Store(true) } // taken back while the image is pulled
	setReset("2026-11-15T10:00:00Z")
	for deadline := time.Now().Add(10 * time.Second); !undone.Load(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the reset's pull never ran")
		}
	}
	time.Sleep(time.Second) // the agent's next steps
	for _, call := range rt.CallLog() {
		if strings.HasPrefix(call, "reset ") || strings.HasPrefix(call, "stop ") {
			t.Fatalf("%q after the reset was taken back: the disk is wiped (%v)", call, rt.CallLog())
		}
	}
}
