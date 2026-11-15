package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/store"
)

// K-108, the worker's half (network lane; the control plane's half is in the control lane,
// hostctl.Beat): a heartbeat the worker sends while held (it judged its control plane older than
// what it saw, or can't judge it) is no contact for its fence, and it says so in the beat itself:
// its Ready condition's reason is hostctl.ReasonWorkerHeld, which the control plane counts as no
// contact either (stamp and Ready kept as stored). A beat sent trusted whose answer the worker
// judged Hold is no fence contact either (the control plane counts it: the safe side). Else a
// worker that reaches only a system node rebuilt from an older backup never fences, while the live
// control plane restarts its opted-in silos elsewhere.
//
// The fix (internal/worker/join.go, Heartbeat), with held the client's judge's view (c.ControlPlane
// implementing interface{ Held() bool }, as agent.Watermark does; false without one):
//
//	heldBefore := held()
//	Ready reason: hostctl.ReasonWorkerHeld if heldBefore, else "WorkerUp"
//	… UpdateStatus …
//	mark contact only if err == nil && !heldBefore && !held()
//
// Both sides then count the same beats, the control plane never fewer, in whatever order the two
// halves land (a worker that never says WorkerHeld is counted on every beat, as before).
func TestK108AHeldWorkersHeartbeatIsNoContact(t *testing.T) {
	t.Skip("K-108, network lane: Heartbeat marks contact while held and never says so in the beat (fix described above)")
	for _, tc := range []struct {
		name          string
		before, after bool
	}{
		{"sent held", true, true},
		{"sent trusted, answered held", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			clk := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
			srv, err := apiserver.New(store.NewMemory(0), clk)
			if err != nil {
				t.Fatal(err)
			}
			c, closeC := srv.InProcess()
			defer closeC()
			h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "w1"},
				Spec: v1.HostSpec{InternalIP: "10.0.0.11", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
			if err := c.Create(ctx, h); err != nil {
				t.Fatal(err)
			}
			j := &heldJudge{says: []bool{tc.before, tc.after}}
			c.ControlPlane = j
			var contact Contact
			bctx, stop := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				Heartbeat(bctx, c, "w1", time.Hour, clk, t.Logf, &contact)
			}()
			var got v1.Host
			for {
				_ = c.Get(ctx, "Host", "", "w1", &got)
				if meta.FindCondition(got.Status.Conditions, "Ready") != nil { // the beat landed
					break
				}
				if ctx.Err() != nil {
					t.Fatal("the heartbeat never landed")
				}
				time.Sleep(time.Millisecond)
			}
			stop()
			<-done
			if !contact.Last().IsZero() {
				t.Fatalf("%s: the heartbeat marked contact at %v", tc.name, contact.Last())
			}
			if r := meta.FindCondition(got.Status.Conditions, "Ready"); tc.before && (r == nil || r.Reason != hostctl.ReasonWorkerHeld) {
				t.Fatalf("%s: the beat doesn't say it is held: %+v", tc.name, r)
			}
		})
	}
}

// heldJudge says, in turn, whether the worker is held (Held), and hands every answer over.
type heldJudge struct {
	mu   sync.Mutex
	says []bool
}

func (*heldJudge) Sending() int64                        { return 0 }
func (*heldJudge) Answer(int64, client.ControlPlaneSeen) {}
func (*heldJudge) Judged(int64, client.ControlPlaneSeen, bool) client.Verdict {
	return client.Accept // handed over, as a held worker's answers are
}
func (j *heldJudge) Held() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.says) == 0 {
		return false
	}
	v := j.says[0]
	if len(j.says) > 1 {
		j.says = j.says[1:]
	}
	return v
}
