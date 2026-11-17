package openshell

import (
	"context"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// A kevasod start pushes a running sandbox's policy once even when the saved hash matches,
// and so does a gateway this process brings back up. After that one push, the hash skips.
func TestARestartPushesTheSavedPolicyOnce(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	if err := r.Create(ctx, kri.Spec{ID: silo}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	p := kri.Policy{Egress: []kri.Endpoint{{Host: "api.github.com", Port: 443}}}
	if err := r.SetPolicy(ctx, silo, p); err != nil {
		t.Fatal(err)
	}
	set := "policy set " + SandboxName(silo)
	n := f.ran(set)
	if n != 1 {
		t.Fatalf("first push ran policy set %d times", n)
	}
	if err := r.SetPolicy(ctx, silo, p); err != nil || f.ran(set) != n {
		t.Fatalf("steady state pushed again (%d)", f.ran(set)-n)
	}
	// kevasod restarted: a new runtime, the same host, the saved hash.
	r2 := newRuntime(f, "")
	if err := r2.SetPolicy(ctx, silo, p); err != nil {
		t.Fatal(err)
	}
	if got := f.ran(set); got != n+1 {
		t.Fatalf("after a restart policy set ran %d times, want %d", got, n+1)
	}
	if err := r2.SetPolicy(ctx, silo, p); err != nil || f.ran(set) != n+1 {
		t.Fatalf("steady state after a restart pushed again (%d)", f.ran(set)-(n+1))
	}
	// This process brings the gateway back up.
	g := Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, silo), Port: BasePort, Driver: DriverVM}
	f.units[g.Unit()] = "inactive"
	if err := r2.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if err := r2.SetPolicy(ctx, silo, p); err != nil {
		t.Fatal(err)
	}
	if got := f.ran(set); got != n+2 {
		t.Fatalf("after the gateway came back policy set ran %d times, want %d", got, n+2)
	}
	if err := r2.SetPolicy(ctx, silo, p); err != nil || f.ran(set) != n+2 {
		t.Fatalf("steady state after the gateway came back pushed again (%d)", f.ran(set)-(n+2))
	}
}
