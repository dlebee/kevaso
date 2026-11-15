package openshell

import (
	"context"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// K-116: a silo whose neighbours on its gateway are all stopped (the gateway down with them) is
// deleted, and so a handoff of it released, without starting the gateway or any neighbour: its
// Delete is done (nothing of it can run; it is no longer listed), and what the gateway's records
// hold of it goes at the gateway's next claimed start, which stops it first. A delete whose
// gateway part keeps failing doesn't fail the neighbours' starts.
func TestASiloWhoseNeighboursAreStoppedIsDeletedWithoutStartingThem(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{DriverVM, DriverDocker} {
		t.Run(d, func(t *testing.T) {
			f := newFake()
			r := newRuntimeOn(f, d)
			started(t, r, siloA, siloB)
			if err := r.SetPolicy(ctx, siloA, kri.Policy{Credentials: []kri.Credential{cred}}); err != nil {
				t.Fatal(err)
			}
			for _, id := range []kri.ID{siloA, siloB} {
				if err := r.Stop(ctx, id); err != nil {
					t.Fatal(err)
				}
			}
			g := gatewayFor(d, siloA)
			starts := f.ran("systemctl start " + g.Unit())
			if err := r.Delete(ctx, siloA); err != nil {
				t.Fatalf("Delete with its neighbours stopped: %v", err)
			}
			if f.ran("systemctl start "+g.Unit()) != starts || f.units[g.Unit()] == "active" {
				t.Fatal("the delete started the gateway (and with it its neighbours)")
			}
			if f.Runs(SandboxName(siloA)) || f.Runs(SandboxName(siloB)) {
				t.Fatal("something runs after the delete")
			}
			if st, err := r.Status(ctx, siloA); err != nil || st.State != kri.Absent {
				t.Fatalf("after its Delete: %v %v, want Absent", st.State, err)
			}
			if ids, _ := r.List(ctx); len(ids) != 1 || ids[0] != siloB {
				t.Fatalf("listed %v after the delete: want only b", ids)
			}
			if err := r.Delete(ctx, siloA); err != nil {
				t.Fatalf("a second Delete: %v", err)
			}
			// b's claimed start: the gateway's part of a's delete fails (its profile can't be
			// deleted); b starts all the same, and nothing of a runs.
			f.failOn = "profile delete"
			if err := r.Start(ctx, siloB); err != nil {
				t.Fatalf("b's start, with a's leftovers failing to go: %v", err)
			}
			if !f.Runs(SandboxName(siloB)) || f.Runs(SandboxName(siloA)) {
				t.Fatalf("after b's start: b runs %v, a runs %v", f.Runs(SandboxName(siloB)), f.Runs(SandboxName(siloA)))
			}
			// Once the gateway can be told, the leftovers go at the next start.
			f.failOn = ""
			if err := r.Stop(ctx, siloB); err != nil {
				t.Fatal(err)
			}
			if err := r.Start(ctx, siloB); err != nil {
				t.Fatal(err)
			}
			if _, ok := f.sandboxes[SandboxName(siloA)]; ok || len(f.providers) != 0 {
				t.Fatalf("a's sandbox %v or its providers %v are still in OpenShell", ok, f.providers)
			}
			if len(f.Glob0(StateDir+"/silos/*")) != 1 {
				t.Fatalf("a's record is kept: %v", f.Glob0(StateDir+"/silos/*"))
			}
		})
	}
}

// The same silo made again here (moved away, then back) before its gateway's part of the delete
// was done: its new start makes a fresh sandbox, never starting the old one with its data.
func TestASiloMadeAgainOverAnUnfinishedDeleteStartsFresh(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB)
	for _, id := range []kri.ID{siloA, siloB} {
		if err := r.Stop(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Delete(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, kri.Spec{ID: siloA, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	creates, deletes := f.ran("sandbox create --name "+SandboxName(siloA)), f.ran("sandbox delete "+SandboxName(siloA))
	if err := r.Start(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if f.ran("sandbox delete "+SandboxName(siloA)) != deletes+1 || f.ran("sandbox create --name "+SandboxName(siloA)) != creates+1 {
		t.Fatalf("the old sandbox was started again rather than made afresh:\n%v", f.cmds[len(f.cmds)-12:])
	}
	if !f.Runs(SandboxName(siloA)) || f.Runs(SandboxName(siloB)) {
		t.Fatalf("a runs %v, b runs %v", f.Runs(SandboxName(siloA)), f.Runs(SandboxName(siloB)))
	}
}
