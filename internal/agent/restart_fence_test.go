package agent_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// After a reboot the fence record (on /run) is gone, and a run whose heartbeats never got through
// has no last contact at all. Zero meant "never fence": the agent and the watcher left a silo
// that asked to stop running while the control plane, counting from the heartbeat stored before the reboot,
// recreated it elsewhere. With no contact yet, the agent counts from its own start.
func TestARunWithNoContactYetStillFences(t *testing.T) {
	srv, _ := apiserver.New(store.NewMemory(0), clock.Real{})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // before the server closes: the agent's watches end first
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	s := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "web", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
			Availability: v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop, After: "30s"}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	rt := fake.New()
	dir := t.TempDir() // empty: a fresh boot
	a := &agent.Agent{Client: c, HostName: "hv1", Runtimes: map[string]kri.Runtime{"cloud-hypervisor": rt}, Clock: clock.Real{},
		LastContact: func() time.Time { return time.Time{} }, // no heartbeat got through in this run
		FenceDir:    dir, Log: t.Logf,
		StopsOnLoss: func(s *v1.Silo) (bool, time.Duration) {
			stop, after := s.StopsOnControlPlaneLoss()
			return stop, after / 20
		}} // 30s → 1.5s
	go a.Run(ctx)
	state := func() kri.State {
		ids, _ := rt.List(ctx)
		if len(ids) == 0 {
			return kri.Absent
		}
		st, _ := rt.Status(ctx, ids[0])
		return st.State
	}
	for state() != kri.Running {
		select {
		case <-ctx.Done():
			t.Fatal("never started")
		case <-time.After(20 * time.Millisecond):
		}
	}
	for state() == kri.Running {
		select {
		case <-ctx.Done():
			r, _ := fence.Read(dir)
			t.Fatalf("never fenced; the record says last contact %v", r.LastContact)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if r, _ := fence.Read(dir); r.LastContact.IsZero() {
		t.Fatal("the record has no last contact: the watcher never fences either")
	}
}
