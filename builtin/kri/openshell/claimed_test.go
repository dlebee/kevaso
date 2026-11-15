package openshell

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// Found on the machines (metal.md, item 5 A6): the rule is that nothing of a silo runs before its
// start claim, and a gateway that starts brings back every sandbox its record says ran. So the
// gateway starts only from a silo's claimed Start. Status, List and Info never started it; Delete,
// Reset and a policy change did, with no claim, after a reboot as at any time. Each now answers
// from the unit's state and Kevaso's own record and leaves the gateway's part (removing a
// sandbox, a reset's delete) to the next claimed Start on that gateway.
func TestOnlyAClaimedStartStartsAGateway(t *testing.T) {
	ctx := context.Background()
	siloC := kri.ID{Namespace: "dev", Name: "c", UID: "uc"}
	siloD := kri.ID{Namespace: "dev", Name: "d", UID: "ud"}
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB, siloC, siloD)
	if err := r.SetPolicy(ctx, siloC, kri.Policy{Credentials: []kri.Credential{cred}}); err != nil {
		t.Fatal(err)
	}
	f.Reboot() // every sandbox was running: the gateway would bring each back
	g := gatewayFor(DriverVM, siloA)
	starts := f.ran("systemctl start " + g.Unit())
	for _, id := range []kri.ID{siloA, siloB, siloC, siloD} {
		if st, err := r.Status(ctx, id); err != nil || st.State != kri.Stopped {
			t.Fatalf("%s after a reboot: %v %v, want Stopped", id.Name, st.State, err)
		}
	}
	_, _ = r.List(ctx)
	_ = r.Info()
	// Delete with its gateway down and neighbours on it: done for Kevaso, with nothing started
	// (K-116); a's sandbox stays in the gateway's home until the gateway's next claimed start.
	if err := r.Delete(ctx, siloA); err != nil {
		t.Fatalf("Delete with its gateway down: %v", err)
	}
	if err := r.Reset(ctx, kri.Spec{ID: siloB, Image: "ubuntu-24.04"}); err != nil {
		t.Fatalf("Reset with its gateway down: %v", err)
	}
	_ = r.SetPolicy(ctx, siloC, kri.Policy{}) // a stopped silo's: it may fail, it mustn't start anything
	if n := f.ran("systemctl start " + g.Unit()); n != starts || f.units[g.Unit()] == "active" {
		t.Fatalf("the gateway was started outside a claimed Start:\n%s", strings.Join(f.cmds, "\n"))
	}
	if st, err := r.Status(ctx, siloA); err != nil || st.State != kri.Absent {
		t.Fatalf("a after its Delete: %v %v, want Absent", st.State, err)
	}
	if st, err := r.Status(ctx, siloB); err != nil || st.State != kri.Created {
		t.Fatalf("b after its Reset: %v %v, want Created", st.State, err)
	}
	if ids, _ := r.List(ctx); len(ids) != 3 {
		t.Fatalf("listed %v: a is deleted", ids)
	}
	// d's claimed Start: the gateway comes up, finishes a's delete, and runs only d.
	if err := r.Start(ctx, siloD); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.sandboxes[SandboxName(siloA)]; ok {
		t.Fatal("a's sandbox is still in OpenShell after d's start")
	}
	if err := r.Delete(ctx, siloA); err != nil {
		t.Fatalf("a's delete, finished by d's start: %v", err)
	}
	if ids, _ := r.List(ctx); len(ids) != 3 {
		t.Fatalf("listed %v after a's delete finished", ids)
	}
	for _, id := range []kri.ID{siloA, siloB, siloC} {
		if f.Runs(SandboxName(id)) {
			t.Fatalf("%s runs with no Start of it", id.Name)
		}
	}
	n := f.ran("sandbox create --name " + SandboxName(siloB))
	if err := r.Start(ctx, siloB); err != nil || f.ran("sandbox create --name "+SandboxName(siloB)) != n+1 || !f.Runs(SandboxName(siloB)) {
		t.Fatalf("b's start after its reset didn't make it afresh: %v", err)
	}
}

// The last silo of a gateway deleted while the gateway is down: nothing needs the gateway's word,
// since the gateway goes whole (its home holds the VM driver's disks, the records and the
// credential store). The Docker driver's containers go by name.
func TestDeletingTheLastSiloWithItsGatewayDownStartsNothing(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{DriverVM, DriverDocker} {
		f := newFake()
		r := newRuntimeOn(f, d)
		started(t, r, silo)
		if err := r.Stop(ctx, silo); err != nil {
			t.Fatal(err)
		}
		g := gatewayFor(d, silo)
		starts := f.ran("systemctl start")
		if err := r.Delete(ctx, silo); err != nil {
			t.Fatal(err)
		}
		if f.ran("systemctl start") != starts {
			t.Fatalf("%s: Delete started the gateway", d)
		}
		if f.files[unitPath(g)] != nil || f.users[g.User()] || len(f.containers) != 0 {
			t.Fatalf("%s: left the unit %v, the user %v, containers %v", d, f.files[unitPath(g)] != nil, f.users[g.User()], f.containers)
		}
	}
}
