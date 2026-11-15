package agent_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// K-117: spec.init.timeout is enforced. A step still running when it runs out (on the agent's
// clock) is stopped and recorded failed (InitFailed StepTimedOut); the silo's main process isn't
// started, and nothing claims a start for it any more.
func TestAnInitStepPastSpecInitTimeoutIsStoppedAndFailed(t *testing.T) {
	rt := fake.NewStrict("hv1", nil)
	rt.HoldInit = func(kri.ID, kri.InitStep) <-chan struct{} { return make(chan struct{}) } // never ends by itself
	hook, clk, get, _ := newK115WithInit(t, rt, &v1.Init{Timeout: "10m", Steps: []v1.InitStep{{Name: "migrate", Run: "sleep 3600"}}})
	waitReal(t, "the step runs", func() bool { return runningStep(rt, get()) == "migrate" })
	clk.Step(9 * time.Minute)
	time.Sleep(50 * time.Millisecond)
	if c := meta.FindCondition(get().Status.Conditions, "InitFailed"); c != nil {
		t.Fatalf("failed before its timeout: %+v", c)
	}
	clk.Step(2 * time.Minute)
	waitReal(t, "InitFailed StepTimedOut", func() bool {
		c := meta.FindCondition(get().Status.Conditions, "InitFailed")
		return c != nil && c.Status == meta.ConditionTrue && c.Reason == "StepTimedOut"
	})
	waitReal(t, "the step stopped", func() bool { return runningStep(rt, get()) == "" })
	c0 := hook.claims.Load()
	for range 60 {
		clk.Step(time.Second)
		time.Sleep(2 * time.Millisecond)
	}
	if n := hook.claims.Load() - c0; n > 0 {
		t.Fatalf("%d start claims after the timed-out step", n)
	}
	for _, c := range rt.CallLog() {
		if c == "start dev/broken" {
			t.Fatal("the main process was started after its init step timed out")
		}
	}
}

func runningStep(rt *fake.Strict, s *v1.Silo) string {
	return rt.RunningInit(kri.ID{Namespace: s.Namespace, Name: s.Name, UID: s.UID})
}
