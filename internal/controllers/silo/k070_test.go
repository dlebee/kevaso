package silo_test

import (
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
)

// K-070, the same shape in the control plane: whatever the silo controller decides for a silo in
// a handoff (its destination lost, unplaced, ready or full hosts, every policy), it never drops or
// replaces movingFrom (moves.Replaces), so the API server's guard can apply to its writes too.
func TestK070TheSiloControllerNeverReplacesAHandoff(t *testing.T) {
	docker := func(h *v1.Host) *v1.Host {
		h.Spec.Components.Worker.Runtimes = []v1.RuntimeSpec{{Name: "docker"}}
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		return h
	}
	full := func(h *v1.Host) *v1.Host { h.Status.Allocatable = v1.Resources{}; return h }
	hostSets := map[string][]*v1.Host{
		"all ready":           {docker(readyHost("S")), docker(readyHost("D")), docker(readyHost("E"))},
		"D lost":              {docker(readyHost("S")), docker(lostHost("D", now.Add(-time.Hour))), docker(readyHost("E"))},
		"D lost, only S":      {docker(readyHost("S")), docker(lostHost("D", now.Add(-time.Hour)))},
		"D lost, S full":      {full(docker(readyHost("S"))), docker(lostHost("D", now.Add(-time.Hour))), docker(readyHost("E"))},
		"S and D lost":        {docker(lostHost("S", now.Add(-time.Hour))), docker(lostHost("D", now.Add(-time.Hour))), docker(readyHost("E"))},
		"no host but S, D":    {docker(readyHost("S")), docker(readyHost("D"))},
		"nothing schedulable": {full(docker(readyHost("S"))), docker(lostHost("D", now.Add(-time.Hour)))},
	}
	n := 0
	for hs, hosts := range hostSets {
		for _, policy := range []string{"", v1.OnHostLossWait, v1.OnHostLossRecreate, v1.OnHostLossMove} {
			for _, placed := range []string{"D", ""} {
				s := newSilo("a")
				s.Spec.Runtime, s.Spec.Container = "docker", &v1.ContainerSource{Image: "app"}
				s.Spec.Availability.OnHostLoss = policy
				s.Status.Host, s.Status.MovingFrom, s.Status.Phase = placed, "S", "Scheduled"
				st := s.Status
				// A few rounds: each decision is the next one's input, as the controller writes it.
				for round := range 3 {
					next, _, _, err := silo.Decide(s, hosts, nil, now.Add(time.Duration(round)*time.Hour))
					if err != nil {
						t.Fatal(err)
					}
					if err := moves.Replaces(st, next); err != nil {
						t.Errorf("%s, policy %q, placed on %q, round %d: %v\n  from %+v\n  to   %+v", hs, policy, placed, round, err, st, next)
					}
					st, s.Status = next, next
					n++
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no cases")
	}
}
