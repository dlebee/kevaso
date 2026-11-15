package silo_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/fence"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/scheduler"
	"kevaso.com/core/sdk/kplugin"
)

// Brainstorm §0.7: the control plane never restarts a silent host's silos by itself. It can't
// tell "dead" from "cut off", and a cut-off host still runs them. It marks them HostUnreachable
// and waits; a person's `kvo move … --confirm-fenced` moves them, and onHostLoss says how
// (Move: with its data; Recreate: a fresh copy). Only a silo that stops itself on control-plane
// loss (spec.availability.onControlPlaneLoss: Stop) may be restarted elsewhere automatically.
//
// The truth table: (opted in or not) x (onHostLoss) x (host silent / back / confirmed fenced),
// over a fake clock from one second to two days of silence.
func TestHostLossTruthTable(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	docker := func(h *v1.Host) *v1.Host {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		return h
	}
	mk := func(policy string, opted bool) *v1.Silo {
		s := newSilo("files")
		s.Spec.Runtime = "docker"
		s.Spec.Container = &v1.ContainerSource{Image: "app"}
		s.Spec.Volumes = []v1.Volume{{Name: "data", Class: "juicefs", Size: "10Gi", MountPath: "/data"}}
		s.Spec.Availability.OnHostLoss = policy
		if opted {
			s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop // after: 2m (the default)
			s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 2*time.Minute, s.Generation)}
			confirmStopped(s, "hv1") // hv1 reported its fence stopped it (without it, it waits: confirmstop_test.go)
		}
		s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.1.2"
		s.Status.Image = &v1.SiloImage{From: "app", Ref: "app:1", Running: "app:1"}
		s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
		return s
	}
	lostAt := now
	silences := []time.Duration{time.Second, 31 * time.Second, 2*time.Minute + time.Second, 2*time.Minute + silo.StopMargin(2*time.Minute) - time.Second,
		10 * time.Minute, time.Hour, 48 * time.Hour}

	for _, opted := range []bool{false, true} {
		for _, policy := range []string{v1.OnHostLossWait, v1.OnHostLossRecreate, v1.OnHostLossMove} {
			name := fmt.Sprintf("opted=%v/onHostLoss=%s", opted, policy)
			t.Run(name+"/silent", func(t *testing.T) {
				s := mk(policy, opted)
				hosts := []*v1.Host{docker(lostHost("hv1", lostAt)), docker(readyHost("hv2"))}
				// Only an opted-in silo whose onHostLoss starts it elsewhere, whose host reported
				// its fence stopped it, once the control plane itself has heard nothing from hv1
				// for after + margin.
				restarts := opted && policy != v1.OnHostLossWait
				earliest := 2*time.Minute + silo.StopMargin(2*time.Minute)
				for _, d := range silences {
					e := env
					e.Silence = func(string) time.Duration { return d }
					st, _, again, err := silo.DecideIn(s, hosts, nil, lostAt.Add(d), e)
					if err != nil {
						t.Fatal(err)
					}
					if restarts && d >= earliest {
						c := meta.FindCondition(st.Conditions, "HostUnreachable")
						if st.Host != "hv2" || c == nil || c.Status != meta.ConditionFalse || !strings.Contains(c.Message, "onControlPlaneLoss: Stop") {
							t.Fatalf("after %v of silence: on %q, %+v", d, st.Host, c)
						}
						if policy == v1.OnHostLossMove && (len(st.Volumes) != 1 || st.Image.Running != "app:1") {
							t.Fatalf("Move: not with its data: %+v", st)
						}
						if policy == v1.OnHostLossRecreate && st.Image.Running != "" {
							t.Fatalf("Recreate: not a fresh copy: %+v", st.Image)
						}
						return
					}
					if restarts && again != earliest-d {
						t.Fatalf("after %v: look again in %v, want %v", d, again, earliest-d)
					}
					// Above all: never started elsewhere without a confirmation.
					if st.Host != "hv1" || st.MovingFrom != "" {
						t.Fatalf("after %v of silence: placed on %q (moving from %q): restarted elsewhere without a confirmation", d, st.Host, st.MovingFrom)
					}
					c := meta.FindCondition(st.Conditions, "HostUnreachable")
					if c == nil || c.Status != meta.ConditionTrue || st.Phase != silo.PhaseUnknown {
						t.Fatalf("after %v: phase %s, HostUnreachable %+v", d, st.Phase, c)
					}
					if !strings.Contains(c.Message, "since") || !strings.Contains(c.Message, "--confirm-fenced") {
						t.Fatalf("after %v: the condition doesn't say since when, or what to do: %q", d, c.Message)
					}
					if policy == v1.OnHostLossRecreate && !strings.Contains(c.Message, "--recreate") {
						t.Fatalf("Recreate: the condition doesn't say a confirmed move recreates: %q", c.Message)
					}
					if meta.FindCondition(st.Conditions, "HostLost") != nil {
						t.Fatal("the old HostLost condition is still written")
					}
					s.Status = st
				}
			})
			t.Run(name+"/back", func(t *testing.T) {
				s := mk(policy, opted)
				st, _, _, _ := silo.DecideIn(s, []*v1.Host{docker(lostHost("hv1", lostAt)), docker(readyHost("hv2"))}, nil, lostAt.Add(time.Hour), env)
				s.Status = st
				st, changed, _, _ := silo.DecideIn(s, []*v1.Host{docker(readyHost("hv1")), docker(readyHost("hv2"))}, nil, lostAt.Add(time.Hour+time.Second), env)
				c := meta.FindCondition(st.Conditions, "HostUnreachable")
				if !changed || st.Host != "hv1" || c == nil || c.Status != meta.ConditionFalse || c.Reason != "HostBack" {
					t.Fatalf("host back: host %q, %+v", st.Host, c)
				}
			})
			t.Run(name+"/confirmed fenced", func(t *testing.T) {
				s := mk(policy, opted)
				hosts := []*v1.Host{docker(lostHost("hv1", lostAt)), docker(readyHost("hv2"))}
				st, _, _, _ := silo.DecideIn(s, hosts, nil, lostAt.Add(time.Minute), env)
				s.Status = st
				// What the API server's move does (internal/apiserver/moves.go).
				req := moves.Request{To: "hv2", ConfirmFenced: true, Recreate: policy == v1.OnHostLossRecreate}
				if _, err := moves.PlanMove(s, moves.Of(s, env.Classes), moves.Request{To: "hv2", Recreate: req.Recreate}, true, false, ""); err == nil {
					t.Fatal("a move off a lost host without --confirm-fenced was accepted")
				}
				plan, err := moves.PlanMove(s, moves.Of(s, env.Classes), req, true, false, "")
				if policy != v1.OnHostLossRecreate {
					// A container never moves with its data (its own files aren't kept): only
					// onHostLoss: Recreate and --recreate move it.
					if !errors.Is(err, moves.ErrNotMovable) {
						t.Fatalf("a plain confirmed move of a container: %v, want ErrNotMovable", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				s.Status = moves.Apply(s.Status, plan)
				for _, d := range silences {
					st, _, _, err := silo.DecideIn(s, hosts, nil, lostAt.Add(time.Minute+d), env)
					if err != nil {
						t.Fatal(err)
					}
					if st.Host != "hv2" {
						t.Fatalf("after the confirmed move, %v later: on %q", d, st.Host)
					}
					s.Status = st
				}
			})
		}
	}
}

// An onControlPlaneLoss: Stop silo is restarted elsewhere only when everything holds: its host's
// fence said it stops this very spec (FenceArmed, this generation), the host reported its fence
// stopped it (FenceStopped), and this control plane's own silence count, not the agent's
// timestamp, reached after + margin.
func TestAStopSiloRestartsOnlyWithItsFenceArmedAndOurOwnSilence(t *testing.T) {
	env := scheduler.Env{Classes: map[string]scheduler.Class{"juicefs": {Plugin: "juicefs", Topology: kplugin.TopologyGlobal}}}
	mk := func() *v1.Silo {
		s := newSilo("one")
		s.Generation = 3
		s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate
		s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = v1.OnControlPlaneLossStop, "45s"
		s.Status.Host, s.Status.Phase = "hv1", "Running"
		s.Status.Conditions = []meta.Condition{fence.ArmedCondition("hv1", 45*time.Second, 3)}
		confirmStopped(s, "hv1")
		return s
	}
	margin := silo.StopMargin(45 * time.Second)
	if margin < 15*time.Second {
		t.Fatalf("margin %v", margin)
	}
	long := func(string) time.Duration { return 45*time.Second + margin }
	hosts := []*v1.Host{lostHost("hv1", now.Add(-time.Hour)), readyHost("hv2")}
	for _, tc := range []struct {
		name    string
		mod     func(*v1.Silo)
		silence func(string) time.Duration
		moves   bool
	}{
		{"all there", func(*v1.Silo) {}, long, true},
		{"one second short, by our clock (the agent's stamp says an hour)", func(*v1.Silo) {}, func(string) time.Duration { return 45*time.Second + margin - time.Second }, false},
		{"no silence count at all", func(*v1.Silo) {}, nil, false},
		{"fence never armed", func(s *v1.Silo) { s.Status.Conditions = s.Status.Conditions[1:] }, long, false},
		{"its host never reported the stop", func(s *v1.Silo) { s.Status.Conditions = s.Status.Conditions[:1] }, long, false},
		{"fence armed False", func(s *v1.Silo) { s.Status.Conditions[0].Status = meta.ConditionFalse }, long, false},
		{"fence armed for an older spec", func(s *v1.Silo) { s.Status.Conditions[0].ObservedGeneration = 2 }, long, false},
		{"fence armed by another host (before a move)", func(s *v1.Silo) { s.Status.Conditions[0] = fence.ArmedCondition("hv0", 45*time.Second, 3) }, long, false},
		{"fence armed with another after", func(s *v1.Silo) { s.Spec.Availability.After = "2m" }, long, false},
		{"not opted in", func(s *v1.Silo) { s.Spec.Availability.OnControlPlaneLoss, s.Spec.Availability.After = "", "" }, long, false},
	} {
		s := mk()
		tc.mod(s)
		e := env
		e.Silence = tc.silence
		st, _, _, err := silo.DecideIn(s, hosts, nil, now, e)
		if err != nil {
			t.Fatal(err)
		}
		if moved := st.Host == "hv2"; moved != tc.moves {
			t.Errorf("%s: on %q", tc.name, st.Host)
		}
		if !tc.moves {
			c := meta.FindCondition(st.Conditions, "HostUnreachable")
			if c == nil || c.Status != meta.ConditionTrue {
				t.Errorf("%s: %+v", tc.name, c)
			}
		}
	}
}
