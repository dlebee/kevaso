package host

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
)

func TestDecide(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	ready := []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, Reason: "WorkerUp"}}
	lost := []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: ReasonLost}}
	for _, c := range []struct {
		name    string
		hb      *time.Time
		conds   []meta.Condition
		changed bool
		again   time.Duration
	}{
		{"fresh", at(5 * time.Second), ready, false, 35 * time.Second},
		{"just under the lease", at(39 * time.Second), ready, false, time.Second},
		{"lease ran out", at(41 * time.Second), ready, true, 40 * time.Second},
		{"already lost", at(5 * time.Minute), lost, false, 40 * time.Second},
		{"never reported", nil, nil, false, 40 * time.Second},
	} {
		h := &v1.Host{Status: v1.HostStatus{LastHeartbeat: c.hb, Conditions: c.conds}}
		cond, changed, again := Decide(h, now, 40*time.Second)
		if changed != c.changed || again != c.again {
			t.Errorf("%s: changed=%v again=%v, want %v %v", c.name, changed, again, c.changed, c.again)
		}
		if changed && (cond.Status != meta.ConditionUnknown || cond.Reason != ReasonLost || cond.Message != "no heartbeat for 41s") {
			t.Errorf("%s: condition %+v", c.name, cond)
		}
	}
}
