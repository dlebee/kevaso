package openshell

import (
	"context"
	"testing"
	"time"
)

// review-batch4 claim 4 (a): a gateway brought up restores every sandbox its record says ran.
// Whenever up brings one up, every sandbox on it but the claimed one is confirmed stopped before
// up returns; if that can't be confirmed the gateway is stopped again and up fails.

// The context ends while up waits for the gateway to answer (kevasod's shutdown, the claim
// ending): before the fix the gateway stayed up with the neighbour it restored running.
func TestAGatewayWhoseStartIsCutIsStoppedAgain(t *testing.T) {
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB)
	f.Reboot()
	ctx, cancel := context.WithCancel(context.Background())
	f.listFails = true // it doesn't answer yet
	r.Sleep = func(time.Duration) { cancel() }
	if err := r.Start(ctx, siloA); err == nil {
		t.Fatal("Start succeeded with its gateway never answering")
	}
	g := gatewayFor(DriverVM, siloA)
	if f.units[g.Unit()] == "active" || f.Runs(SandboxName(siloB)) || f.Runs(SandboxName(siloA)) {
		t.Fatalf("a cut start left the gateway %q, b running %v (no claim of b), a running %v", f.units[g.Unit()], f.Runs(SandboxName(siloB)), f.Runs(SandboxName(siloA)))
	}
}

// A unit already coming up (activating) when the claimed Start looks: before the fix up returned
// as soon as it answered, with no neighbour stopped and no delete finished.
func TestAGatewayFoundComingUpIsSettledLikeAStart(t *testing.T) {
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB)
	f.Reboot()
	g := gatewayFor(DriverVM, siloA)
	f.units[g.Unit()] = "activating"
	f.comesUp = map[string]bool{g.Unit(): true}
	if err := r.Start(context.Background(), siloA); err != nil {
		t.Fatal(err)
	}
	if !f.Runs(SandboxName(siloA)) || f.Runs(SandboxName(siloB)) {
		t.Fatalf("after a's start on a gateway that was coming up: a runs %v, b runs %v (no claim of b)", f.Runs(SandboxName(siloA)), f.Runs(SandboxName(siloB)))
	}
}

// A neighbour's stop that fails: the gateway is stopped again and the start fails. Before the fix
// the start failed with the gateway up and the neighbour running.
func TestANeighbourThatCannotBeStoppedStopsTheGatewayAgain(t *testing.T) {
	for _, d := range []string{DriverVM, DriverDocker} {
		t.Run(d, func(t *testing.T) {
			f := newFake()
			r := newRuntimeOn(f, d)
			started(t, r, siloA, siloB)
			f.Reboot()
			f.failOn = "sandbox stop " + SandboxName(siloB)
			if err := r.Start(context.Background(), siloA); err == nil {
				t.Fatal("Start succeeded although its neighbour couldn't be stopped")
			}
			g := gatewayFor(d, siloA)
			if f.units[g.Unit()] == "active" || f.Runs(SandboxName(siloB)) {
				t.Fatalf("gateway %q, b runs %v: a neighbour that couldn't be stopped runs on", f.units[g.Unit()], f.Runs(SandboxName(siloB)))
			}
		})
	}
}
