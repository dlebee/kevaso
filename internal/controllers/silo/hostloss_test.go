package silo_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
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
			s.Spec.Availability.OnControlPlaneLoss = v1.OnControlPlaneLossStop
		}
		s.Status.Host, s.Status.Phase, s.Status.SiloIP = "hv1", "Running", "10.64.1.2"
		s.Status.Image = &v1.SiloImage{From: "app", Ref: "app:1", Running: "app:1"}
		s.Status.Volumes = []v1.VolumeStatus{{Name: "data", Class: "juicefs", Handle: "vol-1", AttachedTo: "hv1", Mounted: true}}
		return s
	}
	lostAt := now
	silences := []time.Duration{time.Second, 31 * time.Second, 2*time.Minute + time.Second, 10 * time.Minute, time.Hour, 48 * time.Hour}

	for _, opted := range []bool{false, true} {
		for _, policy := range []string{v1.OnHostLossWait, v1.OnHostLossRecreate, v1.OnHostLossMove} {
			name := fmt.Sprintf("opted=%v/onHostLoss=%s", opted, policy)
			t.Run(name+"/silent", func(t *testing.T) {
				s := mk(policy, opted)
				hosts := []*v1.Host{docker(lostHost("hv1", lostAt)), docker(readyHost("hv2"))}
				for _, d := range silences {
					st, _, _, err := silo.DecideIn(s, hosts, nil, lostAt.Add(d), env)
					if err != nil {
						t.Fatal(err)
					}
					// Above all: never started elsewhere without a confirmation (opted-in silos:
					// item 4 of the control lane's work; until then they wait too).
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
