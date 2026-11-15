package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/jointoken"
	"kevaso.com/core/internal/pki"
	"kevaso.com/core/internal/store"
	"kevaso.com/core/internal/worker"
)

// offsetClock is a host's clock: the control plane's fake clock, off by a fixed amount.
type offsetClock struct {
	base *clock.Fake
	off  time.Duration
}

func (c offsetClock) Now() time.Time { return c.base.Now().Add(c.off) }
func (c offsetClock) AfterFunc(d time.Duration, f func()) clock.Timer {
	return c.base.AfterFunc(d, f)
}

// K-106: every heartbeat a worker's write got through with is a contact to the control plane,
// whatever the worker's clock says. A worker whose clock was one heartbeat period behind sent,
// on every other beat, the very stamp the server had stored: the write succeeded (the worker
// marked its fence's contact) and the control plane counted none, losing a period of its margin.
func TestK106EveryAcceptedHeartbeatIsAContact(t *testing.T) {
	const period = worker.DefaultHeartbeat
	type tc struct{ off, every time.Duration }
	var cases []tc
	for _, off := range []time.Duration{-period / 2, -period, -2 * period, period / 2, period, 2 * period} {
		cases = append(cases, tc{off, period})
	}
	// Beats closer than the stamp's second: a retry, or a system node's fast heartbeat.
	cases = append(cases, tc{0, 300 * time.Millisecond}, tc{-period, 300 * time.Millisecond})
	for _, c := range cases {
		t.Run(fmt.Sprintf("worker clock %v, every %v", c.off, c.every), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cp, admin, wc := k106Setup(ctx, t)
			contacts := hostctl.NewContacts(cp.Now())
			hostClock := offsetClock{cp, c.off}

			for beat := 0; beat < 6; beat++ {
				// One heartbeat: Heartbeat sends its first report at once, then waits for a tick
				// that never comes (an hour), until it is stopped.
				var contact worker.Contact
				bctx, stop := context.WithCancel(ctx)
				done := make(chan struct{})
				go func() {
					defer close(done)
					worker.Heartbeat(bctx, wc, "hv1", time.Hour, hostClock, t.Logf, &contact)
				}()
				for contact.Last().IsZero() {
					if ctx.Err() != nil {
						t.Fatalf("beat %d: the heartbeat never got through", beat)
					}
					time.Sleep(time.Millisecond)
				}
				stop()
				<-done
				var got v1.Host
				if err := admin.Get(ctx, "Host", "", "hv1", &got); err != nil {
					t.Fatal(err)
				}
				contacts.Observe(&got, cp.Now())
				if s := contacts.Silence("hv1", cp.Now()); s != 0 {
					t.Fatalf("beat %d (stamp %v): the worker's write got through, and the control plane counts %v of silence", beat, got.Status.LastHeartbeat, s)
				}
				cp.Step(c.every)
			}
		})
	}
}

// K-106, the system node's own heartbeat: it writes its Host's stamp with its own clock, and is
// its worker's fence contact. Two beats within one second (or a clock set back) stored the same
// stamp again: a contact to the node, none to the control plane.
func TestK106ASystemNodesOwnHeartbeatAlwaysStoresANewStamp(t *testing.T) {
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	var h v1.Host
	contacts := hostctl.NewContacts(now)
	for i, at := range []time.Time{now, now.Add(300 * time.Millisecond), now.Add(300 * time.Millisecond), now.Add(-time.Second), now.Add(-time.Second)} {
		setHeartbeat(&h, at)
		contacts.Observe(&h, now.Add(time.Duration(i+1)*time.Second))
		if s := contacts.Silence(h.Name, now.Add(time.Duration(i+1)*time.Second)); s != 0 {
			t.Fatalf("beat %d (sent at %v, stamp %v): no contact to the control plane (%v of silence)", i, at, h.Status.LastHeartbeat, s)
		}
	}
}

// k106Setup is a control plane's API (on a fake clock cp), its admin, and host hv1's worker client
// as the control plane's own worker would have it (written as the host, a worker).
func k106Setup(ctx context.Context, t *testing.T) (*clock.Fake, *client.Client, *client.Client) {
	t.Helper()
	st := store.NewMemory(0)
	b, _ := json.Marshal(ClusterIdentity{ID: "c", History: "h1", Epoch: 1})
	if _, err := st.Create(ctx, identityKey, b); err != nil {
		t.Fatal(err)
	}
	cp := clock.NewFake(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	ca, err := pki.NewCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apiserver.NewWithAuth(st, cp, &apiserver.Auth{CA: ca, Tokens: &jointoken.Issuer{Store: st, Clock: cp}})
	if err != nil {
		t.Fatal(err)
	}
	admin, closeA := srv.InProcess()
	t.Cleanup(closeA)
	h := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: "hv1"},
		Spec: v1.HostSpec{InternalIP: "10.0.0.11", Components: v1.HostComponents{Worker: &v1.WorkerSpec{}}}}
	if err := admin.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	wc, closeW := workerClient(srv, st, agent.OpenWatermark("", nil), "hv1")
	t.Cleanup(closeW)
	return cp, admin, wc
}

// K-106, the server's half: a host's status write that carries the stamp it read (any write made
// from its own copy, or a worker whose clock reads what the server stamped last) is still a
// heartbeat, stamped anew.
func TestK106AHostsWriteCarryingTheStoredStampIsAContact(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cp, admin, wc := k106Setup(ctx, t)
	const period = worker.DefaultHeartbeat
	// The API server's clock between beats: the fourth beat lands on another system node, whose
	// clock is a period behind, so it reads just what the first node stamped last. The leader
	// counts on its own clock, a period per beat.
	steps := []time.Duration{period, period, 0, period, period}
	leader := cp.Now()
	contacts := hostctl.NewContacts(leader)
	for beat, step := range steps {
		var cur v1.Host
		if err := wc.Get(ctx, "Host", "", "hv1", &cur); err != nil {
			t.Fatal(err)
		}
		if beat == 0 {
			t0 := cp.Now()
			cur.Status.LastHeartbeat = &t0
		}
		if err := wc.UpdateStatus(ctx, &cur); err != nil {
			t.Fatal(err)
		}
		var got v1.Host
		if err := admin.Get(ctx, "Host", "", "hv1", &got); err != nil {
			t.Fatal(err)
		}
		contacts.Observe(&got, leader)
		if s := contacts.Silence("hv1", leader); s != 0 {
			t.Fatalf("beat %d (sent %v, stored %v): accepted, and the control plane counts %v of silence", beat, cur.Status.LastHeartbeat, got.Status.LastHeartbeat, s)
		}
		cp.Step(step)
		leader = leader.Add(period)
	}
}
