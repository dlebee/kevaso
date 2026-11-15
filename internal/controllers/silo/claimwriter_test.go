package silo_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/engine"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/internal/store"
)

func claim(host string, at time.Time) meta.Condition {
	msg := "starting on " + host + " at " + at.Format(time.RFC3339Nano)
	if host == "" {
		msg = "starting " + at.Format(time.RFC3339Nano)
	}
	return meta.Condition{Type: silo.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting", Message: msg, ObservedGeneration: 1, LastTransitionTime: at}
}

// Review of the start claim, item 2: a worker may write any condition on a silo placed on it,
// so a claim must count only for the host the silo is placed on, and only when it names that
// host. hv1 writing "starting on hv2" again and again must not reset hv2's silence (which would
// postpone the restart of every opted-in silo on hv2 for as long as hv1 keeps writing).
func TestAClaimNamingAnotherHostIsNoContactOfThatHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	clk := clock.NewFake(t0)
	srv, err := apiserver.New(store.NewMemory(0), clk)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	_ = c.Create(ctx, &v1.Namespace{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "dev"}})
	for _, n := range []string{"hv1", "hv2"} {
		h := readyHost(n)
		st := h.Status
		if err := c.Create(ctx, h); err != nil {
			t.Fatal(err)
		}
		h.Status = st
		if err := c.UpdateStatus(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	s := newSilo("forger")
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	s.Status.Conditions = []meta.Condition{claim("hv2", t0)}
	if err := c.UpdateStatus(ctx, s); err != nil {
		t.Fatal(err)
	}
	contacts := hostctl.NewContacts(t0)
	clk.Step(time.Hour)
	ctl := &silo.Controller{Client: c, Silos: frozen(ctx, t, c, "Silo"), Hosts: frozen(ctx, t, c, "Host"), Clock: clk, Contacts: contacts}
	if _, err := ctl.Reconcile(ctx, engine.Key{Kind: "Silo", Namespace: "dev", Name: "forger"}); err != nil {
		t.Fatal(err)
	}
	if got := contacts.Silence("hv2", clk.Now()); got != time.Hour {
		t.Fatalf("hv2's silence is %v after hv1 wrote a claim naming it, want an hour: a claim counted for a host that didn't write it", got)
	}
	if got := contacts.Silence("hv1", clk.Now()); got != time.Hour {
		t.Fatalf("hv1's silence is %v: a claim naming another host counted for it", got)
	}
}

// A claim that names no host, or another host than the silo's, doesn't pin the silo (it stands
// for nothing), and the restart says it was ignored.
func TestAClaimThatIsNotTheHostsOwnIsIgnoredAndSaidSo(t *testing.T) {
	for _, by := range []string{"", "hv2"} {
		s := newSilo("one")
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, s.Generation), claim(by, now)}
		confirmStopped(s, "hv1") // hv1 reported its fence stopped it, under that claim
		env := scheduler.Env{Silence: func(string) time.Duration { return time.Hour }, StartClaimAge: func(*v1.Silo) time.Duration { return time.Second }}
		st, _, _, err := silo.DecideIn(s, []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2"), readyHost("hv3")}, nil, now, env)
		if err != nil {
			t.Fatal(err)
		}
		if st.Host == "hv1" || st.Host == "" {
			t.Fatalf("claim by %q: still on %q; a claim that isn't hv1's own pinned it", by, st.Host)
		}
		u := meta.FindCondition(st.Conditions, silo.CondHostUnreachable)
		if u == nil || !strings.Contains(u.Message, "ignored") {
			t.Fatalf("claim by %q: the ignored claim isn't said: %+v", by, u)
		}
	}
}

// A claim left over from a host the silo was on is dropped when the control plane places it
// elsewhere: after the move, a new leader (who has never seen it, so would count it as fresh)
// must not find a standing claim on the new placement.
func TestAPlacementChangeClearsTheOldClaim(t *testing.T) {
	s := newSilo("one")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
	s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
	s.Status.Host, s.Status.Phase = "hv1", "Running"
	s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, s.Generation), claim("hv1", now.Add(-time.Hour))}
	confirmStopped(s, "hv1")
	env := scheduler.Env{Silence: func(string) time.Duration { return time.Hour }, StartClaimAge: func(*v1.Silo) time.Duration { return time.Hour }}
	st, _, _, err := silo.DecideIn(s, []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}, nil, now, env)
	if err != nil {
		t.Fatal(err)
	}
	if st.Host != "hv2" {
		t.Fatalf("not restarted elsewhere: %q", st.Host)
	}
	if c := meta.FindCondition(st.Conditions, silo.CondStartClaim); c != nil {
		t.Fatalf("hv1's claim is still on the silo placed on hv2: %+v", c)
	}
}
