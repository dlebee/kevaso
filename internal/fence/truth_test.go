package fence

import (
	"testing"
	"time"

	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/sdk/kri"
)

// The full truth table of the fence's decision: a silo is stopped exactly when the host needs
// fencing, its contact is known and older than FenceAfter, its policy lets the control plane start
// it elsewhere (Recreate, Move), and this fence hasn't stopped it already.
func TestDecideTruthTable(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	after := DefaultAfter
	ages := map[string]time.Duration{"fresh": time.Second, "at FenceAfter": after, "just past": after + time.Millisecond, "long gone": time.Hour}
	for _, fenceOn := range []bool{false, true} {
		for _, never := range []bool{false, true} {
			for ageName, age := range ages {
				for _, policy := range []string{"", v1.OnHostLossWait, v1.OnHostLossRecreate, v1.OnHostLossMove, "recreate"} {
					for _, done := range []bool{false, true} {
						r := Record{Fence: fenceOn, Silos: []Silo{{ID: kri.ID{Namespace: "d", Name: "s", UID: "u"}, Runtime: "docker", OnHostLoss: policy}}}
						if !never {
							r.LastContact = now.Add(-age)
						}
						got := len(Decide(r, now, after, map[string]bool{"u": done})) == 1
						want := fenceOn && !never && age > after && (policy == v1.OnHostLossRecreate || policy == v1.OnHostLossMove) && !done
						if got != want {
							t.Errorf("fence %v, never in contact %v, contact %s, policy %q, done %v: stop %v, want %v",
								fenceOn, never, ageName, policy, done, got, want)
						}
					}
				}
			}
		}
	}
}

// Who needs fencing, by the cluster's shape: a host whose silos the rest could start elsewhere
// while it's cut off.
func TestAppliesTruthTable(t *testing.T) {
	cp := func(stateOnly bool) *v1.ControlPlaneSpec { return &v1.ControlPlaneSpec{StateOnly: stateOnly} }
	host := func(name string, c *v1.ControlPlaneSpec, worker bool) v1.Host {
		h := v1.Host{}
		h.Name = name
		h.Spec.Components.ControlPlane = c
		if worker {
			h.Spec.Components.Worker = &v1.WorkerSpec{}
		}
		return h
	}
	for _, c := range []struct {
		name  string
		hosts []v1.Host
		want  bool
	}{
		{"not registered yet", []v1.Host{host("cp", cp(false), false)}, true},
		{"a worker, control plane elsewhere", []v1.Host{host("me", nil, true), host("cp", cp(false), false)}, true},
		{"no worker", []v1.Host{host("me", cp(false), false), host("cp", cp(false), false), host("cp2", cp(false), false)}, false},
		{"one node", []v1.Host{host("me", cp(false), true)}, false},
		{"two system nodes: no majority without me", []v1.Host{host("me", cp(false), true), host("cp", cp(false), false)}, false},
		{"three system nodes", []v1.Host{host("me", cp(false), true), host("cp", cp(false), false), host("cp2", cp(false), false)}, true},
		{"three, the others state-only: nobody serves the API", []v1.Host{host("me", cp(false), true), host("s1", cp(true), false), host("s2", cp(true), false)}, false},
		{"three, one other serves the API", []v1.Host{host("me", cp(false), true), host("s1", cp(true), false), host("s2", cp(false), false)}, true},
		{"four: three others are a majority", []v1.Host{host("me", cp(false), true), host("a", cp(false), false), host("b", cp(false), false), host("c", cp(true), false)}, true},
	} {
		self := "me"
		if got := Applies(c.hosts, self); got != c.want {
			t.Errorf("%s: Applies %v, want %v", c.name, got, c.want)
		}
	}
}
