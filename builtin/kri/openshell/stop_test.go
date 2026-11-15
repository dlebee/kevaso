package openshell

import (
	"context"
	"errors"
	"testing"
)

func newRuntimeOn(f *fake, driver string) *Runtime {
	r := newRuntime(f, "")
	if driver == DriverDocker {
		r.Name, r.Driver = "openshell-container", DriverDocker
	}
	return r
}

// Item 2: stop means stopped. After Stop returns, nothing of the sandbox runs (by looking: the
// VM under its unit, the container under dockerd), and it stays stopped across a start of its
// gateway (for a neighbour) and a reboot. Stop was `sandbox stop` only: the gateway stayed up and
// enabled and its word was taken for it.
func TestAfterStopNothingOfItRuns(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{DriverVM, DriverDocker} {
		f := newFake()
		r := newRuntimeOn(f, d)
		started(t, r, siloA, siloB)
		if err := r.Stop(ctx, siloA); err != nil {
			t.Fatal(err)
		}
		if f.Runs(SandboxName(siloA)) || !f.Runs(SandboxName(siloB)) {
			t.Fatalf("%s: after Stop(a): a runs %v, b runs %v", d, f.Runs(SandboxName(siloA)), f.Runs(SandboxName(siloB)))
		}
		if err := r.Stop(ctx, siloB); err != nil {
			t.Fatal(err)
		}
		f.Reboot()
		if f.Runs(SandboxName(siloA)) || f.Runs(SandboxName(siloB)) {
			t.Fatalf("%s: a stopped sandbox runs after a reboot", d)
		}
		if err := r.Start(ctx, siloB); err != nil { // the gateway starts again, for b
			t.Fatal(err)
		}
		if f.Runs(SandboxName(siloA)) || !f.Runs(SandboxName(siloB)) {
			t.Fatalf("%s: after a start of b: a runs %v, b runs %v", d, f.Runs(SandboxName(siloA)), f.Runs(SandboxName(siloB)))
		}
	}
}

// Item 2: the gateway's word isn't taken for it. A Docker-driver gateway that says Stopped while
// the container runs on: Stop stops the container itself, and fails if it still runs.
func TestStopLooksInsteadOfTakingTheGatewaysWord(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntimeOn(f, DriverDocker)
	started(t, r, siloA, siloB)
	f.stopLies = true
	if err := r.Stop(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if f.Runs(SandboxName(siloA)) {
		t.Fatal("Stop returned while the container runs: it took the gateway's word")
	}
}

// Item 2: a gateway that doesn't answer while its unit is up can neither stop the sandbox nor
// say whether it runs: Stop fails (it said nil and the sandbox ran on). Its unit down (a crash),
// the VM driver's sandbox can't run, and the Docker driver's container is stopped by Kevaso.
func TestStopWithASilentGateway(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{DriverVM, DriverDocker} {
		f := newFake()
		r := newRuntimeOn(f, d)
		started(t, r, siloA, siloB)
		g := gatewayFor(d, siloA)
		f.hung[g.Name()] = true
		if err := r.Stop(ctx, siloA); err == nil || !errors.Is(err, ErrGatewaySilent) {
			t.Fatalf("%s: Stop with a hung gateway: %v (runs %v), want ErrGatewaySilent", d, err, f.Runs(SandboxName(siloA)))
		}
		f.hung[g.Name()] = false
		f.Crash(g.Name())
		if err := r.Stop(ctx, siloA); err != nil {
			t.Fatalf("%s: Stop with its gateway down: %v", d, err)
		}
		if f.Runs(SandboxName(siloA)) {
			t.Fatalf("%s: runs after Stop with its gateway down", d)
		}
	}
}
