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
)

// K-110: a control plane restored from a backup taken between a reset's request (or an image
// change) and its completion says the request is still due. This host made the disk afresh for
// that very request already and recorded so: nothing is wiped a second time, and the status says
// it is done.
func TestARestoredStatusDoesNotReplayAResetOrImageChangeAlreadyApplied(t *testing.T) {
	for _, tc := range []struct {
		name string
		ask  func(*v1.Silo)
		done func(*v1.SiloImage) bool
	}{
		{"reset", func(s *v1.Silo) { s.Spec.Reset = "2026-11-15T10:00:00Z" },
			func(im *v1.SiloImage) bool { return im.Reset == "2026-11-15T10:00:00Z" }},
		{"image", func(s *v1.Silo) { s.Spec.Container.Image = "registry.example/app:2" },
			func(im *v1.SiloImage) bool { return im.Running == "registry.example/app:2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newHistoryRig(t)
			r.start(r.rt)
			r.trusted(seenA)
			r.id = r.place(r.cA, "hv1")
			get := func() *v1.Silo {
				var s v1.Silo
				if err := r.cA.Get(r.ctx, "Silo", "dev", "single", &s); err != nil {
					t.Fatal(err)
				}
				return &s
			}
			write := func(f func(*v1.Silo) error) {
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
			// What a backup taken while the request is due holds of status.image: as it is until
			// the request is applied (for an image, with the new source resolved).
			before := *get().Status.Image
			write(func(s *v1.Silo) error { tc.ask(s); return r.cA.Update(r.ctx, s) })
			if tc.name == "image" { // the control plane's part: the new source resolved
				write(func(s *v1.Silo) error {
					before.From, before.Ref = s.Spec.From(), s.Spec.From()
					s.Status.Image.From, s.Status.Image.Ref = before.From, before.Ref
					return r.cA.UpdateStatus(r.ctx, s)
				})
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
			r.waitFor("the request is applied", func() bool {
				s := get()
				return s.Status.Image != nil && tc.done(s.Status.Image) && meta.IsTrue(s.Status.Conditions, "Ready")
			})
			if n := resets(); n != 1 {
				t.Fatalf("%d resets for one request", n)
			}
			// The restore: a new history, the same silo and request, its status.image from before.
			r.cp.switchTo(r.srvA, seenRestor)
			r.trusted(seenRestor)
			write(func(s *v1.Silo) error { im := before; s.Status.Image = &im; return r.cA.UpdateStatus(r.ctx, s) })
			for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
				if n := resets(); n != 1 {
					t.Fatalf("the disk was made afresh again (%d resets) for a request already applied here, on a restored status", n)
				}
				r.clk.Step(time.Second)
			}
			r.waitFor("the status says it is applied", func() bool {
				s := get()
				return s.Status.Image != nil && tc.done(s.Status.Image)
			})
			if n := resets(); n != 1 {
				t.Fatalf("%d resets", n)
			}
			// The record is on disk, for the next kevasod too.
			if b, _ := os.ReadFile(filepath.Join(filepath.Dir(r.file), agent.AppliedFile)); !strings.Contains(string(b), r.id.UID) {
				t.Fatalf("the applied request isn't recorded on disk: %s", b)
			}
		})
	}
}
