package openshell

import (
	"context"
	"strings"
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

func policyHashOf(t *testing.T, r *Runtime) string {
	t.Helper()
	s, ok := r.load(silo)
	if !ok {
		t.Fatal("silo state gone")
	}
	return s.PolicyHash
}

// A policy written while the gateway is down stays pending: the file has it, the saved hash does
// not, and the next start of the existing sandbox applies it. A push that fails once is retried;
// the hash is recorded only after a push succeeds. After that, a matching hash skips.
func TestAPolicyChangeWhileTheGatewayIsDownIsAppliedWhenItReturns(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	if err := r.Create(ctx, kri.Spec{ID: silo}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	first := kri.Policy{Egress: []kri.Endpoint{{Host: "api.github.com", Port: 443}}}
	if err := r.SetPolicy(ctx, silo, first); err != nil {
		t.Fatal(err)
	}
	saved := policyHashOf(t, r)
	set := "policy set " + SandboxName(silo)
	n := f.ran(set)
	if n != 1 || saved == "" {
		t.Fatalf("first push: policy set %d times, hash %q", n, saved)
	}

	// A push that fails once is not recorded. The retry is, and then the hash skips.
	f.failOn = "policy set"
	retried := kri.Policy{Egress: []kri.Endpoint{{Host: "api.gitlab.com", Port: 443}}}
	if err := r.SetPolicy(ctx, silo, retried); err == nil {
		t.Fatal("SetPolicy succeeded while policy set fails")
	}
	if got := string(f.files[policyPath(silo)]); !strings.Contains(got, `host: "api.gitlab.com"`) {
		t.Fatalf("a failed push did not keep the pending policy:\n%s", got)
	}
	if got := policyHashOf(t, r); got != saved {
		t.Fatalf("hash recorded %q after a failed push", got)
	}
	f.failOn = ""
	if err := r.SetPolicy(ctx, silo, retried); err != nil {
		t.Fatal(err)
	}
	if got, want := policyHashOf(t, r), PolicyHash(retried); got != want {
		t.Fatalf("hash after the push recovered %q, want %q", got, want)
	}
	saved = policyHashOf(t, r)
	n = f.ran(set)
	if err := r.SetPolicy(ctx, silo, retried); err != nil || f.ran(set) != n {
		t.Fatalf("steady state pushed again (%d)", f.ran(set)-n)
	}

	g := Gateway{Key: GatewayKey(DriverVM, ScopeNamespace, silo), Port: BasePort, Driver: DriverVM}
	f.units[g.Unit()] = "inactive"
	next := kri.Policy{Egress: []kri.Endpoint{{Host: "files.pythonhosted.org", Port: 443}}}
	if err := r.SetPolicy(ctx, silo, next); err == nil {
		t.Fatal("SetPolicy succeeded while the gateway was down")
	}
	if got := string(f.files[policyPath(silo)]); !strings.Contains(got, `host: "files.pythonhosted.org"`) {
		t.Fatalf("the pending policy was not written while the gateway was down:\n%s", got)
	}
	if got := policyHashOf(t, r); got != saved {
		t.Fatalf("hash recorded %q while the push did not succeed (was %q)", got, saved)
	}
	if f.ran(set) != n {
		t.Fatal("policy set ran while the gateway was down")
	}

	// The push fails once on the way back, then the start applies the pending file.
	f.failOn = "policy set"
	if err := r.Start(ctx, silo); err == nil {
		t.Fatal("the start applied the policy while policy set fails")
	}
	if got := policyHashOf(t, r); got != saved {
		t.Fatalf("hash recorded %q after a failed push", got)
	}
	tried := f.ran(set)
	if tried != n+1 {
		t.Fatalf("the failed start tried to apply the policy %d times, want 1", tried-n)
	}
	f.failOn = ""
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := f.ran(set); got != tried+1 {
		t.Fatalf("starting the existing sandbox applied the pending policy %d times, want 1", got-tried)
	}
	if got := string(f.files[policyPath(silo)]); !strings.Contains(got, `host: "files.pythonhosted.org"`) {
		t.Fatalf("the pending policy was not the file that was applied:\n%s", got)
	}
	if err := r.SetPolicy(ctx, silo, next); err != nil {
		t.Fatal(err)
	}
	if got, want := policyHashOf(t, r), PolicyHash(next); got != want {
		t.Fatalf("hash after the gateway recovered %q, want %q", got, want)
	}
	n = f.ran(set)
	if err := r.SetPolicy(ctx, silo, next); err != nil || f.ran(set) != n {
		t.Fatalf("steady state pushed again (%d)", f.ran(set)-n)
	}

	// A grant that changes while the sandbox is stopped is applied when it starts.
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	stopped := kri.Policy{Egress: []kri.Endpoint{{Host: "registry.npmjs.org", Port: 443}}}
	if err := r.StagePolicy(ctx, silo, stopped); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if got := f.ran(set); got != n+1 {
		t.Fatalf("starting the stopped sandbox applied the staged policy %d times, want 1", got-n)
	}
	if got := string(f.files[policyPath(silo)]); !strings.Contains(got, `host: "registry.npmjs.org"`) {
		t.Fatalf("the sandbox was not started with the staged policy:\n%s", got)
	}
	if err := r.SetPolicy(ctx, silo, stopped); err != nil {
		t.Fatal(err)
	}
	if got, want := policyHashOf(t, r), PolicyHash(stopped); got != want {
		t.Fatalf("hash after the stopped silo started %q, want %q", got, want)
	}
}
