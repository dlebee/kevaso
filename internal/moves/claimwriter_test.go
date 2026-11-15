package moves

import (
	"errors"
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

// Review of the start claim, item 2, at the source: a host writes a start claim only in its own
// name. hv1 writing one that names hv2 (or no host) is refused; its own is allowed.
func TestAHostClaimsAStartOnlyInItsOwnName(t *testing.T) {
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	old := v1.SiloStatus{Host: "hv1", Phase: "Scheduled"}
	for _, tc := range []struct {
		msg string
		ok  bool
	}{
		{"starting on hv1 at " + at.Format(time.RFC3339Nano), true},
		{"starting on hv2 at " + at.Format(time.RFC3339Nano), false},
		{"starting soon", false},
	} {
		next := old
		next.Conditions = []meta.Condition{{Type: CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting", Message: tc.msg, LastTransitionTime: at}}
		err := HostWrite(old, next, "hv1")
		if (err == nil) != tc.ok {
			t.Errorf("%q: %v, want ok=%v", tc.msg, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrHostWrite) {
			t.Errorf("%q: %v is not ErrHostWrite", tc.msg, err)
		}
	}
	// A claim already there, unchanged, by whatever name: not this write's.
	stood := old
	stood.Conditions = []meta.Condition{{Type: CondStartClaim, Status: meta.ConditionTrue, Message: "starting on hv0 at x"}}
	next := stood
	next.Phase = "Running"
	if err := HostWrite(stood, next, "hv1"); err != nil {
		t.Fatalf("an unchanged claim: %v", err)
	}
	if h, ok := StartClaimHost("starting on hv1 at " + at.Format(time.RFC3339Nano)); !ok || h != "hv1" {
		t.Fatalf("StartClaimHost: %q %v", h, ok)
	}
}
