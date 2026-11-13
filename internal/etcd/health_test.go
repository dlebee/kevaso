package etcd_test

import (
	"testing"
	"time"

	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/etcd"
)

func TestJudge(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	host := func(name string, hb *time.Time) v1.Host {
		return v1.Host{ObjectMeta: meta.ObjectMeta{Name: name}, Status: v1.HostStatus{LastHeartbeat: hb}}
	}
	hosts := []v1.Host{host("a", at(5*time.Second)), host("b", at(time.Minute)), host("c", nil), host("d", at(0))}
	ms := []etcd.Member{
		{ID: 1, Name: "a"},                // fresh heartbeat
		{ID: 2, Name: "b"},                // stale
		{ID: 3, Name: "c"},                // never heartbeat
		{ID: 4, Name: "d", Learner: true}, // started learner
		{ID: 5, Learner: true},            // added, not started
		{ID: 6, Name: "gone"},             // no Host at all
	}
	want := []bool{true, false, false, true, false, false}
	got := etcd.Judge(ms, hosts, now, 40*time.Second)
	for i, m := range got {
		if m.Healthy != want[i] {
			t.Errorf("member %d (%q): healthy %v, want %v", m.ID, m.Name, m.Healthy, want[i])
		}
	}
	if ms[0].Healthy {
		t.Error("Judge changed its input")
	}
}

func TestNeedsRotation(t *testing.T) {
	end := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		now  time.Time
		want bool
	}{
		{end.Add(-31 * 24 * time.Hour), false},
		{end.Add(-30 * 24 * time.Hour), true},
		{end.Add(time.Hour), true},
	} {
		if got := etcd.NeedsRotation(end, c.now, etcd.RenewBefore); got != c.want {
			t.Errorf("%v: %v, want %v", c.now, got, c.want)
		}
	}
}
