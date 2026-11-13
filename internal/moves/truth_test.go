package moves

import (
	"fmt"
	"math/rand"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// Who may start a silo when (design §0.3): the full truth table of MayStart, and properties of
// what a host's status write may change, over random statuses. Together: a copy starts only on
// the host the silo is placed on, never while another host still has to let go, and no host can
// place a silo, take one from another, or say another host's volume is unmounted.

func TestMayStartTruthTable(t *testing.T) {
	hosts := []string{"", "a", "b"}
	for _, placed := range hosts {
		for _, from := range hosts {
			for _, asker := range []string{"a", "b"} {
				s := &v1.Silo{Status: v1.SiloStatus{Host: placed, MovingFrom: from}}
				// The spec: placed on the asker, and nobody else is still letting go of it.
				want := placed == asker && (from == "" || from == asker)
				if got := MayStart(s, asker); got != want {
					t.Errorf("placed %q, moving from %q: %s may start: %v, want %v", placed, from, asker, got, want)
				}
				if placed != "" && from != "" && from != placed && MayStart(s, asker) {
					t.Errorf("placed %q, %q still letting go: %s may start", placed, from, asker)
				}
			}
		}
	}
}

func genStatus(r *rand.Rand) v1.SiloStatus {
	hosts := []string{"", "a", "b", "c"}
	st := v1.SiloStatus{Host: hosts[r.Intn(len(hosts))], MovingFrom: hosts[r.Intn(len(hosts))], Phase: "Running"}
	for i := range r.Intn(3) {
		st.Volumes = append(st.Volumes, v1.VolumeStatus{Name: fmt.Sprintf("v%d", i), AttachedTo: hosts[r.Intn(len(hosts))], Mounted: r.Intn(2) == 0})
	}
	return st
}

// mutate changes a random part of st: the host's write as an attacker or a bug would make it.
func mutate(r *rand.Rand, st v1.SiloStatus) v1.SiloStatus {
	hosts := []string{"", "a", "b", "c"}
	st.Volumes = append([]v1.VolumeStatus(nil), st.Volumes...)
	for range 1 + r.Intn(3) {
		switch r.Intn(7) {
		case 0:
			st.Host = hosts[r.Intn(len(hosts))]
		case 1:
			st.MovingFrom = hosts[r.Intn(len(hosts))]
		case 2:
			if len(st.Volumes) > 0 {
				i := r.Intn(len(st.Volumes))
				st.Volumes[i].Mounted = !st.Volumes[i].Mounted
			}
		case 3:
			if len(st.Volumes) > 0 {
				st.Volumes[r.Intn(len(st.Volumes))].AttachedTo = hosts[r.Intn(len(hosts))]
			}
		case 4:
			st.Volumes = append(st.Volumes, v1.VolumeStatus{Name: "new"})
		case 5:
			st.Phase = "Stopped"
		case 6:
			st.SiloIP = "10.64.0.9"
		}
	}
	return st
}

func TestPropertyHostWrites(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	runs := 20000
	if testing.Short() {
		runs = 2000
	}
	for i := 0; i < runs; i++ {
		old := genStatus(r)
		next := mutate(r, old)
		for _, host := range []string{"a", "b", "c"} {
			if HostWrite(old, next, host) != nil {
				continue
			}
			fail := func(why string) {
				t.Fatalf("%s may write %+v over %+v: %s", host, next, old, why)
			}
			handingOff := old.MovingFrom == host && old.Host != host
			switch {
			case next.Host != old.Host:
				fail("it placed the silo")
			case old.Host != host && !handingOff:
				fail("not its silo")
			case next.MovingFrom != old.MovingFrom && !(handingOff && next.MovingFrom == ""):
				fail("it changed who is letting go")
			case len(next.Volumes) != len(old.Volumes):
				fail("it changed which volumes there are")
			}
			for j, o := range old.Volumes {
				n := next.Volumes[j]
				if n.Name != o.Name || n.AttachedTo != o.AttachedTo {
					fail("it moved a volume")
				}
				if n.Mounted != o.Mounted && o.AttachedTo != host {
					fail("it changed another host's mounted flag")
				}
				if handingOff && n.Mounted && !o.Mounted {
					fail("letting go, it mounted a volume")
				}
			}
			if handingOff {
				want1, _ := LetGo(old, host)
				want2, _ := Released(old, host)
				if fmt.Sprint(next) != fmt.Sprint(want1) && fmt.Sprint(next) != fmt.Sprint(want2) {
					fail("handing off, it wrote something other than letting go")
				}
			}
		}
	}
}

// A move, step by step, with the old host up: the new host may start the silo only once the old
// one has said it let go, and the old one may then write nothing more.
func TestHandoffSequence(t *testing.T) {
	s := &v1.Silo{Status: v1.SiloStatus{Host: "a", Phase: "Running", Volumes: []v1.VolumeStatus{{Name: "data", AttachedTo: "a", Mounted: true}}}}
	m := Movability{WithData: true}
	p, err := PlanMove(s, m, Request{To: "b"}, false, "")
	if err != nil || !p.Handoff {
		t.Fatalf("plan: %+v %v", p, err)
	}
	s.Status = Apply(s.Status, p)
	if MayStart(s, "b") || MayStart(s, "a") {
		t.Fatal("someone may start it before a let go")
	}
	// a unmounts, then lets go.
	next, ok := LetGo(s.Status, "a")
	if !ok || HostWrite(s.Status, next, "a") != nil {
		t.Fatalf("a's unmount refused: %v", HostWrite(s.Status, next, "a"))
	}
	s.Status = next
	if MayStart(s, "b") {
		t.Fatal("b may start while a hasn't let go")
	}
	next, ok = Released(s.Status, "a")
	if !ok || HostWrite(s.Status, next, "a") != nil {
		t.Fatal("a's release refused")
	}
	s.Status = next
	if !MayStart(s, "b") || MayStart(s, "a") {
		t.Fatalf("after release: b %v, a %v", MayStart(s, "b"), MayStart(s, "a"))
	}
	again := s.Status
	again.Phase = "Running"
	if HostWrite(s.Status, again, "a") == nil {
		t.Fatal("a still writes the silo after letting go")
	}
	// The old host lost instead: no handoff, and only with the operator's word it's stopped.
	s = &v1.Silo{Status: v1.SiloStatus{Host: "a", Phase: "Running"}}
	if _, err := PlanMove(s, m, Request{To: "b"}, true, ""); err != ErrNeedsFenced {
		t.Fatalf("a lost, not confirmed: %v", err)
	}
	p, err = PlanMove(s, m, Request{To: "b", ConfirmFenced: true}, true, "")
	if err != nil || p.Handoff {
		t.Fatalf("a lost, confirmed: %+v %v", p, err)
	}
	s.Status = Apply(s.Status, p)
	if !MayStart(s, "b") {
		t.Fatal("confirmed fenced: b may not start")
	}
}
