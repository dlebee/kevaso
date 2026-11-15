package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-117: a spec edit while an init step runs waits for it: the step is neither killed nor run
// again (its claim's renewal went on through the edit), and once it is done the silo starts on the
// new spec, its steps not run again.
func TestASpecEditWaitsForARunningInitStep(t *testing.T) {
	rt := fake.NewStrict("hv1", nil)
	release := make(chan struct{})
	rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return release }
	_, clk, get, c := newK115WithInit(t, rt, &v1.Init{Steps: []v1.InitStep{{Name: "migrate", Run: "long-migration"}}})
	waitReal(t, "the step runs", func() bool { return runningStep(rt, get()) == "migrate" })
	for {
		cur := get()
		cur.Spec.Resources.Memory = "512Mi"
		err := c.Update(context.Background(), cur)
		if err == nil {
			break
		}
		if !client.IsConflict(err) {
			t.Fatal(err)
		}
	}
	for range 40 { // past several claim renewals on the agent's clock
		clk.Step(time.Second)
		time.Sleep(5 * time.Millisecond)
	}
	if runningStep(rt, get()) != "migrate" {
		t.Fatalf("the spec edit ended the running init step: %v", rt.CallLog())
	}
	close(release)
	waitReal(t, "it runs on the new spec", func() bool {
		clk.Step(100 * time.Millisecond)
		s := get()
		return s.Status.Phase == agent.PhaseRunning && meta.IsTrue(s.Status.Conditions, "Ready")
	})
	n := 0
	for _, l := range rt.CallLog() {
		if strings.HasPrefix(l, "init migrate ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the step was begun %d times: %v", n, rt.CallLog())
	}
}
