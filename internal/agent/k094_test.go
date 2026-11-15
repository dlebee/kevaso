package agent_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
	"kevaso.com/core/sdk/kri/fake"
)

// fenced is a k088 rig whose agent is cut off from the control plane on demand, with every silo
// opted in to stop after 1s.
func fenced(t *testing.T) (*k088, *atomic.Bool) {
	k := newK088(t, nil)
	var cut atomic.Bool
	k.a.LastContact = func() time.Time {
		if cut.Load() {
			return time.Now().Add(-time.Hour)
		}
		return time.Now()
	}
	k.a.StopsOnLoss = func(*v1.Silo) (bool, time.Duration) { return true, time.Second }
	return k, &cut
}

func (k *k088) running() bool {
	st, err := k.rt.Status(k.ctx, k.id)
	return err == nil && st.State == kri.Running
}

// K-094: the fence counts a silo stopped only when Status answers "not running" after the kill,
// and looks again on every pass: a silo that runs again during the outage (a start in flight, a
// runtime that brings it back by itself) is killed again.
func TestTheFenceLooksAgainOnEveryPass(t *testing.T) {
	k, cut := fenced(t)
	go k.a.Run(k.ctx)
	k.place()
	k.waitFor("the silo runs", k.running)
	cut.Store(true)
	k.waitFor("the fence stopped it", func() bool { return !k.running() })
	if err := k.rt.Start(k.ctx, k.id); err != nil { // it comes back by itself
		t.Fatal(err)
	}
	k.waitFor("the fence stopped it again", func() bool { return !k.running() })
}

// K-094: a kill that Status can't confirm (an engine that can't say) isn't done: it is tried on
// every pass, and once contact is back the Host says which silos the fence couldn't confirm
// stopped, so a person knows two copies may have run.
func TestAKillThatIsNeverConfirmedIsReported(t *testing.T) {
	k, cut := fenced(t)
	if err := k.c.Create(k.ctx, &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}); err != nil {
		t.Fatal(err)
	}
	go k.a.Run(k.ctx)
	k.place()
	k.waitFor("the silo runs", k.running)
	k.rt.RefuseKill(fake.ErrKillRefused)
	cut.Store(true)
	time.Sleep(3 * time.Second) // several passes
	n := 0
	for _, c := range k.rt.CallLog() {
		if c == "kill (refused) dev/single" {
			n++
		}
	}
	if n < 2 {
		t.Fatalf("a kill that failed was tried %d times: %v", n, k.rt.CallLog())
	}
	cut.Store(false)
	k.waitFor("the Host says the fence couldn't stop it", func() bool {
		var h v1.Host
		_ = k.c.Get(k.ctx, "Host", "", "hv1", &h)
		c := meta.FindCondition(h.Status.Conditions, agent.ConditionFenceUnconfirmed)
		return c != nil && c.Status == meta.ConditionTrue
	})
}

// K-094: every runtime call of the fence has a timeout, and one hung engine stalls no other
// silo's fence.
func TestAHungEngineStallsNoOtherFence(t *testing.T) {
	k, cut := fenced(t)
	other := fake.NewStrict("hv1", k.w)
	k.a.Runtimes["podman"] = other
	go k.a.Run(k.ctx)
	k.place()
	s2 := &v1.Silo{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Silo"}, ObjectMeta: meta.ObjectMeta{Name: "second", Namespace: "dev"},
		Spec: v1.SiloSpec{Runtime: "podman", Container: &v1.ContainerSource{Image: "ubuntu-24.04"}, Resources: v1.Resources{CPU: 1, Memory: "256Mi"}}}
	if err := k.c.Create(k.ctx, s2); err != nil {
		t.Fatal(err)
	}
	s2.Status.Host, s2.Status.Phase = "hv1", "Scheduled"
	if err := k.c.UpdateStatus(k.ctx, s2); err != nil {
		t.Fatal(err)
	}
	id2 := kri.ID{Namespace: "dev", Name: "second", UID: s2.UID}
	runs2 := func() bool { st, err := other.Status(k.ctx, id2); return err == nil && st.State == kri.Running }
	k.waitFor("both run", func() bool { return k.running() && runs2() })
	hung := make(chan struct{})
	defer close(hung)
	k.rt.HangKill(hung) // docker's kill never returns
	cut.Store(true)
	for i := 0; i < 2; i++ { // the second time: a later pass, the first kill still hung
		k.waitFor("the other runtime's silo is stopped (calls: "+strings.Join(other.CallLog(), ", ")+")", func() bool { return !runs2() })
		if err := other.Start(k.ctx, id2); err != nil {
			t.Fatal(err)
		}
	}
}
