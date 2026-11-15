package moves

import (
	"errors"
	"testing"

	v1 "kevaso.com/core/api/v1"
)

// K-070: a silo moving S → D whose source S hasn't let go. Any write that drops or replaces
// movingFrom lets a host start it while S still runs it: drain D (movingFrom: D, placed on E: D
// never ran it and lets go at once, E starts), or a write clearing it. Only S itself ends the
// handoff (Released, judged by HostWrite), or it lands back on S, or a person's confirmed-fenced
// move (PlanMove, which the move handler applies without this check).
func TestK070AHandoffUnderWayIsNeverReplaced(t *testing.T) {
	moving := v1.SiloStatus{Host: "D", MovingFrom: "S", Phase: "Scheduled"}
	for _, tc := range []struct {
		name string
		old  v1.SiloStatus
		next v1.SiloStatus
		ok   bool
	}{
		{"drain of the destination: movingFrom replaced", moving, v1.SiloStatus{Host: "", MovingFrom: "D", Phase: "Pending"}, false},
		{"placed elsewhere with movingFrom cleared", moving, v1.SiloStatus{Host: "E", Phase: "Scheduled"}, false},
		{"movingFrom cleared in place", moving, v1.SiloStatus{Host: "D", Phase: "Scheduled"}, false},
		{"a new destination, the handoff kept (K-005)", moving, v1.SiloStatus{Host: "E", MovingFrom: "S", Phase: "Scheduled"}, true},
		{"unplaced, the handoff kept", moving, v1.SiloStatus{MovingFrom: "S", Phase: "Pending"}, true},
		{"back on its source: nothing to hand off", moving, v1.SiloStatus{Host: "S", Phase: "Scheduled"}, true},
		{"other fields only", moving, v1.SiloStatus{Host: "D", MovingFrom: "S", Phase: "Running"}, true},
		{"movingFrom its own host is no handoff: restarted elsewhere after its fence", v1.SiloStatus{Host: "H", MovingFrom: "H"}, v1.SiloStatus{Host: "X"}, true},
		{"no handoff: a drain may start one", v1.SiloStatus{Host: "D", Phase: "Running"}, v1.SiloStatus{MovingFrom: "D", Phase: "Pending"}, true},
	} {
		err := Replaces(tc.old, tc.next)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Replaces = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrMoving) {
			t.Errorf("%s: %v is not ErrMoving", tc.name, err)
		}
	}
}

// Begin is the check before a handoff starts: never while one is under way.
func TestK070BeginRefusesWhileAHandoffIsUnderWay(t *testing.T) {
	if err := Begin(v1.SiloStatus{Host: "D", MovingFrom: "S"}); !errors.Is(err, ErrMoving) {
		t.Fatalf("Begin during S → D: %v, want ErrMoving", err)
	}
	if err := Begin(v1.SiloStatus{Host: "D", MovingFrom: "D"}); err != nil {
		t.Fatalf("Begin with movingFrom its own host: %v", err)
	}
	if err := Begin(v1.SiloStatus{Host: "D"}); err != nil {
		t.Fatalf("Begin with no handoff: %v", err)
	}
	// A handoff that Begin allows is one Replaces allows: the two rules agree.
	if err := Replaces(v1.SiloStatus{Host: "D"}, v1.SiloStatus{MovingFrom: "D"}); err != nil {
		t.Fatal(err)
	}
}
