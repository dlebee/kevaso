package siloset_test

import (
	"sort"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/controllers/siloset"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func newSet(instances int, mut ...func(*v1.SiloSet)) *v1.SiloSet {
	s := &v1.SiloSet{ObjectMeta: meta.ObjectMeta{Name: "rpc", Namespace: "web3", UID: "set-uid", Generation: 1},
		Spec: v1.SiloSetSpec{Instances: instances,
			Template: v1.SiloTemplate{Labels: map[string]string{"app": "rpc"}, SiloSpec: v1.SiloSpec{Runtime: "cloud-hypervisor", VM: &v1.VMSource{Image: "geth:v1"}}}}}
	for _, m := range mut {
		m(s)
	}
	return s
}

// materialize makes the planned instances exist, Ready, created i seconds after t0.
func materialize(set *v1.SiloSet, p siloset.Plan, have []*v1.Silo, ready bool) []*v1.Silo {
	byName := map[string]*v1.Silo{}
	for _, s := range have {
		byName[s.Name] = s
	}
	for _, d := range p.Delete {
		delete(byName, d)
	}
	for _, u := range p.Update {
		n := *u
		if !equalSpec(byName[u.Name], u) {
			n.Generation++
		}
		byName[u.Name] = &n
		if !ready {
			n.Status.Conditions = nil
		}
	}
	for i, c := range p.Create {
		n := *c
		n.UID = n.Name
		n.Generation = 1
		ts := t0.Add(time.Duration(len(byName)+i) * time.Second)
		n.CreationTimestamp = &ts
		byName[n.Name] = &n
	}
	var out []*v1.Silo
	for _, s := range byName {
		if ready {
			meta.SetCondition(&s.Status.Conditions, meta.Condition{Type: "Ready", Status: meta.ConditionTrue, ObservedGeneration: s.Generation}, t0)
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func equalSpec(a, b *v1.Silo) bool {
	return a != nil && a.Spec.From() == b.Spec.From() && a.Spec.Reset == b.Spec.Reset
}

func names(l []*v1.Silo) []string {
	var out []string
	for _, s := range l {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func TestScaleOutAndIn(t *testing.T) {
	set := newSet(3)
	p := siloset.Decide(set, nil)
	if got := names(p.Create); len(got) != 3 || got[0] != "rpc-0" || got[2] != "rpc-2" {
		t.Fatalf("create: %v", got)
	}
	c := p.Create[0]
	if c.Spec.From() != "geth:v1" || c.Labels["app"] != "rpc" || c.Labels[v1.LabelSiloSet] != "rpc" || c.Labels[v1.LabelRevision] != set.Revision() ||
		len(c.OwnerReferences) != 1 || c.OwnerReferences[0].UID != "set-uid" {
		t.Fatalf("instance: %+v", c)
	}
	insts := materialize(set, p, nil, true)
	if p := siloset.Decide(set, insts); len(p.Create)+len(p.Update)+len(p.Delete) != 0 || p.Status.Ready != 3 {
		t.Fatalf("steady: %+v", p)
	}

	// Scale in, NewestFirst: rpc-2 then rpc-1; a protected one stays and the condition says so.
	insts[1].Labels[v1.LabelProtected] = "true" // rpc-1
	set.Spec.Instances = 1
	p = siloset.Decide(set, insts)
	if len(p.Delete) != 2 || p.Delete[0] != "rpc-2" || p.Delete[1] != "rpc-0" {
		t.Fatalf("scale in with rpc-1 protected: %v", p.Delete)
	}
	set.Spec.Instances, set.Spec.ScaleInPolicy = 2, v1.OldestFirst
	delete(insts[1].Labels, v1.LabelProtected)
	if p = siloset.Decide(set, insts); len(p.Delete) != 1 || p.Delete[0] != "rpc-0" {
		t.Fatalf("OldestFirst: %v", p.Delete)
	}
	// Not Ready ones go first, whatever the policy.
	insts[2].Status.Conditions = nil
	if p = siloset.Decide(set, insts); len(p.Delete) != 1 || p.Delete[0] != "rpc-2" {
		t.Fatalf("not ready first: %v", p.Delete)
	}
	// Everything protected: blocked, said so.
	for _, s := range insts {
		s.Labels[v1.LabelProtected] = "true"
	}
	set.Spec.Instances = 0
	p = siloset.Decide(set, insts)
	if c := meta.FindCondition(p.Status.Conditions, "Ready"); len(p.Delete) != 0 || c == nil || c.Reason != "ScaleInBlocked" {
		t.Fatalf("all protected: %+v", p)
	}

	// A gap is refilled with the lowest free name.
	set = newSet(3)
	insts = materialize(set, siloset.Decide(set, nil), nil, true)
	insts = append(insts[:1], insts[2:]...) // rpc-1 gone
	if p = siloset.Decide(set, insts); len(p.Create) != 1 || p.Create[0].Name != "rpc-1" {
		t.Fatalf("refill: %v", names(p.Create))
	}
}

func TestStandby(t *testing.T) {
	set := newSet(2, func(s *v1.SiloSet) { s.Spec.Standby = 1 })
	p := siloset.Decide(set, nil)
	if len(p.Create) != 3 || p.Create[2].Labels[v1.LabelStandby] != "true" || p.Create[0].Labels[v1.LabelStandby] != "" {
		t.Fatalf("standby: %v", names(p.Create))
	}
	insts := materialize(set, p, nil, true)
	if p = siloset.Decide(set, insts); p.Status.Ready != 2 || p.Status.Standby != 1 || p.Status.Instances != 3 {
		t.Fatalf("status: %+v", p.Status)
	}
	// One more instance: the standby one is taken (it's booted already), and a new standby made.
	set.Spec.Instances = 3
	p = siloset.Decide(set, insts)
	if len(p.Update) != 1 || p.Update[0].Name != "rpc-2" || p.Update[0].Labels[v1.LabelStandby] != "" ||
		len(p.Create) != 1 || p.Create[0].Name != "rpc-3" || p.Create[0].Labels[v1.LabelStandby] != "true" {
		t.Fatalf("promote: update %v create %v", names(p.Update), names(p.Create))
	}
}

// rollout runs plans to the end, the agent making every update Ready at once, and returns the
// most instances that were ever not Ready at the same time, and the most that existed.
func rollout(t *testing.T, set *v1.SiloSet, insts []*v1.Silo) (maxDown, maxTotal int, final []*v1.Silo) {
	t.Helper()
	for step := 0; step < 50; step++ {
		p := siloset.Decide(set, insts)
		if len(p.Create)+len(p.Update)+len(p.Delete) == 0 {
			return maxDown, maxTotal, insts
		}
		insts = materialize(set, p, insts, false) // updated ones are down until the agent's done
		down := 0
		for _, s := range insts {
			if !siloset.Ready(s) && s.Labels[v1.LabelStandby] != "true" {
				down++
			}
		}
		maxDown, maxTotal = max(maxDown, down), max(maxTotal, len(insts))
		insts = materialize(set, siloset.Plan{}, insts, true)
	}
	t.Fatal("the rollout never finished")
	return
}

func TestRollingUpdate(t *testing.T) {
	set := newSet(4, func(s *v1.SiloSet) { s.Spec.UpgradePolicy = v1.UpgradeRolling })
	insts := materialize(set, siloset.Decide(set, nil), nil, true)
	set.Spec.Template.VM = &v1.VMSource{Image: "geth:v2"}
	down, total, final := rollout(t, set, insts)
	if down != 1 || total != 4 {
		t.Fatalf("StopFirst, maxUnavailable 1: %d down at once, %d instances at most", down, total)
	}
	for _, s := range final {
		if s.Spec.From() != "geth:v2" || s.Labels[v1.LabelRevision] != set.Revision() {
			t.Fatalf("%s not updated: %+v", s.Name, s.Spec)
		}
	}

	// StartFirst: one extra first, never fewer than 4 Ready, back to 4 at the end.
	set.Spec.Template.VM, set.Spec.Update = &v1.VMSource{Image: "geth:v3"}, v1.SiloSetUpdate{Strategy: v1.StartFirst, MaxUnavailable: ptr(0)}
	down, total, final = rollout(t, set, final)
	if total != 5 || len(final) != 4 {
		t.Fatalf("StartFirst: %d at most, %d after", total, len(final))
	}
	ready := 0
	for _, s := range final {
		if s.Spec.From() == "geth:v3" {
			ready++
		}
	}
	if ready != 4 {
		t.Fatalf("StartFirst: %d on v3", ready)
	}
	_ = down

	// Exclusive instances: one at a time, never a surge, whatever is asked.
	set.Spec.Template.Exclusive = true
	set.Spec.Template.VM, set.Spec.Update = &v1.VMSource{Image: "geth:v4"}, v1.SiloSetUpdate{MaxUnavailable: ptr(3), MaxSurge: ptr(2)}
	down, total, _ = rollout(t, set, final)
	if down != 1 || total != 4 {
		t.Fatalf("exclusive: %d down at once, %d at most", down, total)
	}
}

func TestManualUpgradeAndReset(t *testing.T) {
	set := newSet(2) // Manual
	insts := materialize(set, siloset.Decide(set, nil), nil, true)
	set.Spec.Template.VM = &v1.VMSource{Image: "geth:v2"}
	p := siloset.Decide(set, insts)
	if len(p.Update) != 0 {
		t.Fatalf("Manual updated %v", names(p.Update))
	}
	if c := meta.FindCondition(p.Status.Conditions, "Ready"); c == nil || c.Reason != "UpdateAvailable" || p.Status.Updated != 0 {
		t.Fatalf("Manual should say an update is available: %+v", p.Status)
	}
	// New instances get the new image.
	set.Spec.Instances = 3
	if p = siloset.Decide(set, insts); len(p.Create) != 1 || p.Create[0].Spec.From() != "geth:v2" {
		t.Fatalf("new instance image: %+v", p.Create)
	}
	set.Spec.Instances = 2
	// kvo reset siloset --rolling: every instance, one at a time, onto the current image.
	set.Spec.Reset = "2026-11-12T10:00:00Z"
	down, _, final := rollout(t, set, insts)
	if down != 1 {
		t.Fatalf("rolling reset: %d down at once", down)
	}
	for _, s := range final {
		if s.Spec.From() != "geth:v2" || s.Spec.Reset != set.Spec.Reset {
			t.Fatalf("%s not reset: %+v", s.Name, s.Spec)
		}
	}
}

func TestInstanceSpec(t *testing.T) {
	set := newSet(1, func(s *v1.SiloSet) { s.Spec.Spread = "host" })
	sp := set.InstanceSpec()
	if sp.From() != "geth:v1" || sp.Placement.Spread == nil || sp.Placement.Spread.Selector[v1.LabelSiloSet] != "rpc" {
		t.Fatalf("instance spec: %+v", sp)
	}
	r := set.Revision()
	set.Spec.Instances = 9 // not part of an instance
	if set.Revision() != r {
		t.Fatal("the instance count changed the revision")
	}
	set.Spec.Template.Labels["tier"] = "b"
	if set.Revision() == r {
		t.Fatal("a template label didn't change the revision")
	}
	if v1.InstanceIndex("rpc", "rpc-12") != 12 || v1.InstanceIndex("rpc", "rpc-pool-1") != -1 || v1.InstanceIndex("rpc", "rpc-01") != -1 {
		t.Fatal("InstanceIndex")
	}
}

func ptr(i int) *int { return &i }
