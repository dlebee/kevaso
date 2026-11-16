package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/agent"
	"kevaso.com/core/sdk/kri"
)

// K-127: a reset (or a new image) that a create satisfied, because this host had no copy yet, is
// recorded with the resets this host has applied. A control plane restored from a backup taken
// while that request was still due does not make the disk afresh again.
func TestAResetSatisfiedByACreateIsNotAppliedAgainAfterARestore(t *testing.T) {
	img := "ubuntu-24.04"
	const resetAt = "2026-11-16T04:00:00Z"
	for _, tc := range []struct {
		name string
		ask  func(*v1.Silo)
		due  v1.SiloImage
		done func(*v1.SiloImage) bool
	}{
		{"reset", func(s *v1.Silo) { s.Spec.Reset = resetAt },
			v1.SiloImage{From: img, Ref: img, Running: img},
			func(im *v1.SiloImage) bool { return im.Reset == resetAt }},
		{"image", func(s *v1.Silo) { s.Spec.Container.Image = "registry.example/app:2" },
			v1.SiloImage{From: "registry.example/app:2", Ref: "registry.example/app:2", Running: img},
			func(im *v1.SiloImage) bool { return im.Running == "registry.example/app:2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newHistoryRig(t)
			r.id = r.place(r.cA, "hv1")
			write := func(f func(*v1.Silo) error) {
				t.Helper()
				for {
					var s v1.Silo
					if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &s); err != nil {
						t.Fatal(err)
					}
					err := f(&s)
					if err == nil {
						return
					}
					if !client.IsConflict(err) {
						t.Fatal(err)
					}
				}
			}
			// The request is due, and this host has no copy: Create makes the disk.
			write(func(s *v1.Silo) error { tc.ask(s); return r.cA.Update(r.ctx, s) })
			write(func(s *v1.Silo) error { im := tc.due; s.Status.Image = &im; return r.cA.UpdateStatus(r.ctx, s) })
			r.start(r.rt)
			r.trusted(seenA)
			get := func() *v1.Silo {
				t.Helper()
				var s v1.Silo
				if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &s); err != nil {
					t.Fatal(err)
				}
				return &s
			}
			resets := func() int {
				n := 0
				for _, c := range r.rt.CallLog() {
					if strings.HasPrefix(c, "reset ") {
						n++
					}
				}
				return n
			}
			r.waitFor("the create satisfied the request", func() bool {
				s := get()
				st, _ := r.rt.Status(r.ctx, r.id)
				return st.State == kri.Running && s.Status.Image != nil && tc.done(s.Status.Image) && meta.IsTrue(s.Status.Conditions, "Ready")
			})
			if n := resets(); n != 0 {
				t.Fatalf("the request reset the disk (%d resets); a create should have satisfied it", n)
			}
			// The restore: a new history, the same request, its status.image from while it was due.
			r.cp.switchTo(r.srvA, seenRestor)
			r.trusted(seenRestor)
			write(func(s *v1.Silo) error { im := tc.due; s.Status.Image = &im; return r.cA.UpdateStatus(r.ctx, s) })
			for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
				if n := resets(); n != 0 {
					t.Fatalf("the disk was made afresh (%d resets) for a request a create already satisfied here", n)
				}
				r.clk.Step(time.Second)
			}
			r.waitFor("the status says the request is satisfied", func() bool {
				s := get()
				return s.Status.Image != nil && tc.done(s.Status.Image)
			})
			if n := resets(); n != 0 {
				t.Fatalf("%d resets", n)
			}
			if b, _ := os.ReadFile(filepath.Join(filepath.Dir(r.file), agent.AppliedFile)); !strings.Contains(string(b), r.id.UID) {
				t.Fatalf("the request a create satisfied isn't recorded on disk: %s", b)
			}
		})
	}
}

// K-127: an applied-resets file that can't be read is not an empty record. A reset the store says
// is still due (a restore's replay of one this host may already have applied) is not applied, and
// the host says why.
func TestAnUnreadableAppliedRecordRefusesAReplayedReset(t *testing.T) {
	r := newHistoryRig(t)
	stop := r.start(r.rt)
	r.trusted(seenA)
	r.id = r.place(r.cA, "hv1")
	get := func() *v1.Silo {
		t.Helper()
		var s v1.Silo
		if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &s); err != nil {
			t.Fatal(err)
		}
		return &s
	}
	write := func(f func(*v1.Silo) error) {
		t.Helper()
		for {
			err := f(get())
			if err == nil {
				return
			}
			if !client.IsConflict(err) {
				t.Fatal(err)
			}
		}
	}
	r.waitFor("it runs", func() bool { return meta.IsTrue(get().Status.Conditions, "Ready") })
	before := *get().Status.Image
	const resetAt = "2026-11-16T05:00:00Z"
	write(func(s *v1.Silo) error { s.Spec.Reset = resetAt; return r.cA.Update(r.ctx, s) })
	resets := func() int {
		n := 0
		for _, c := range r.rt.CallLog() {
			if strings.HasPrefix(c, "reset ") {
				n++
			}
		}
		return n
	}
	r.waitFor("the reset is applied", func() bool {
		s := get()
		return s.Status.Image != nil && s.Status.Image.Reset == resetAt && meta.IsTrue(s.Status.Conditions, "Ready")
	})
	if n := resets(); n != 1 {
		t.Fatalf("%d resets for one request", n)
	}
	stop()
	if err := os.WriteFile(filepath.Join(filepath.Dir(r.file), agent.AppliedFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(func(s *v1.Silo) error { im := before; s.Status.Image = &im; return r.cA.UpdateStatus(r.ctx, s) })
	r.start(r.rt)
	r.trusted(seenA)
	r.waitFor("the replay is refused because the record can't be read", func() bool {
		if n := resets(); n != 1 {
			t.Fatalf("a replayed reset was applied (%d resets) while the record of applied resets can't be read", n)
		}
		c := meta.FindCondition(get().Status.Conditions, "Updated")
		return c != nil && c.Status == meta.ConditionFalse && strings.Contains(c.Message, "can't be read")
	})
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if n := resets(); n != 1 {
			t.Fatalf("a replayed reset was applied (%d resets) while the record of applied resets can't be read", n)
		}
		r.clk.Step(time.Second)
	}
}
