package openshell

import (
	"context"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

var (
	siloA = kri.ID{Namespace: "dev", Name: "a", UID: "ua"}
	siloB = kri.ID{Namespace: "dev", Name: "b", UID: "ub"}
)

func gatewayFor(driver string, id kri.ID) Gateway {
	return Gateway{Key: GatewayKey(driver, ScopeNamespace, id), Port: BasePort, Driver: driver}
}

func created(t *testing.T, r *Runtime, ids ...kri.ID) {
	t.Helper()
	for _, id := range ids {
		if err := r.Create(context.Background(), kri.Spec{ID: id, Image: "ubuntu-24.04"}); err != nil {
			t.Fatal(err)
		}
	}
}

func started(t *testing.T, r *Runtime, ids ...kri.ID) {
	t.Helper()
	created(t, r, ids...)
	for _, id := range ids {
		if err := r.Start(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
}

// K-080, K-087 (item 1): the gateway is Kevaso's to start and stop. Its unit was enabled at
// boot and Restart=on-failure, so a reboot or a crash brought its sandboxes back with no start
// claim and without Kevaso's knowledge. Its unit is never enabled and never restarts itself.
func TestTheGatewayUnitIsNeitherEnabledNorRestartedBySystemd(t *testing.T) {
	for _, d := range []string{DriverVM, DriverDocker} {
		u := Gateway{Key: d + "-host", Port: BasePort, Driver: d}.UnitFile()
		if !strings.Contains(u, "\nRestart=no\n") || strings.Contains(u, "[Install]") || strings.Contains(u, "WantedBy") {
			t.Errorf("%s unit: want Restart=no and no [Install] section:\n%s", d, u)
		}
		if !strings.Contains(u, "\nKillMode=control-group\n") {
			t.Errorf("%s unit: its stop must take every process of it (KillMode=control-group)", d)
		}
	}
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	if f.ran("systemctl enable") != 0 {
		t.Fatalf("a gateway unit was enabled:\n%s", strings.Join(f.cmds, "\n"))
	}
	g := gatewayFor(DriverVM, silo)
	f.Crash(g.Name())
	if f.units[g.Unit()] == "active" || f.Runs(SandboxName(silo)) {
		t.Fatal("a crashed gateway came back by itself, its sandbox with it")
	}
	f.Reboot()
	if f.units[g.Unit()] == "active" || f.Runs(SandboxName(silo)) {
		t.Fatal("the gateway started at boot, before and without kevasod")
	}
}

// Item 1: Create runs before the agent's start claim (the agent creates, then claims, then
// starts). It started the gateway, and a gateway that starts brings back what its record says
// ran: a silo's code before any claim. Create readies the gateway (user, files, unit) and starts
// nothing; Start, which runs after the claim, starts it.
func TestCreateStartsNoGateway(t *testing.T) {
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA)
	f.Reboot()
	created(t, r, siloB) // a new silo in the same namespace, before its claim
	g := gatewayFor(DriverVM, siloA)
	if f.units[g.Unit()] == "active" || f.Runs(SandboxName(siloA)) {
		t.Fatalf("Create started the gateway (and with it %s, unclaimed):\n%s", SandboxName(siloA), strings.Join(f.cmds, "\n"))
	}
	if !strings.Contains(string(f.files["/etc/systemd/system/"+g.Unit()]), "ExecStart=") || !f.users[g.User()] {
		t.Fatal("Create didn't ready the gateway's unit and user")
	}
}

// Item 1: kevasod stops the gateway when its last sandbox that should run is stopped, and starts
// it again when one must run.
func TestTheLastStopStopsTheGatewayAndAStartStartsIt(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB)
	g := gatewayFor(DriverVM, siloA)
	if err := r.Stop(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if f.units[g.Unit()] != "active" || !f.Runs(SandboxName(siloB)) {
		t.Fatal("stopping one silo stopped its neighbour's gateway")
	}
	if err := r.Stop(ctx, siloB); err != nil {
		t.Fatal(err)
	}
	if f.units[g.Unit()] == "active" {
		t.Fatal("the gateway runs on with no sandbox that should run")
	}
	if err := r.Start(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if !f.Runs(SandboxName(siloA)) || f.Runs(SandboxName(siloB)) {
		t.Fatalf("after Start(a): a runs %v, b runs %v (b was stopped)", f.Runs(SandboxName(siloA)), f.Runs(SandboxName(siloB)))
	}
}

// Item 1: a gateway that crashed while its silos should run is recovered by Kevaso, which knows:
// the VM driver's silo reads Stopped (its unit is down, so nothing of it runs) and Start brings
// the gateway and the sandbox back, after the agent's claim.
func TestACrashedGatewayIsRecoveredByKevaso(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	g := gatewayFor(DriverVM, silo)
	f.Crash(g.Name())
	st, err := r.Status(ctx, silo)
	if err != nil || st.State != kri.Stopped || !strings.Contains(st.Message, g.Name()) {
		t.Fatalf("after a crash: %v %q %v, want Stopped, saying why", st.State, st.Message, err)
	}
	if err := r.Start(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.Status(ctx, silo); st.State != kri.Running || !f.Runs(SandboxName(silo)) {
		t.Fatalf("after Start: %v, runs %v", st.State, f.Runs(SandboxName(silo)))
	}
}

// Item 1, what stays open (a finding, not fixed here): a namespace's silos share one gateway, and
// a gateway that starts restores every sandbox its record says ran. After a reboot, the start of
// one silo (after its claim) brings its neighbours back before their claims. The runtime stops
// them again at once (they come back Stopped, so the agent claims and starts them as usual), but
// their code ran for that moment. Only OpenShell can close it (a gateway that restores nothing),
// or gatewayScope: silo.
func TestAStartedGatewayStopsTheNeighboursItRestored(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, siloA, siloB)
	f.Reboot()
	if err := r.Start(ctx, siloA); err != nil {
		t.Fatal(err)
	}
	if !f.Runs(SandboxName(siloA)) {
		t.Fatal("a doesn't run")
	}
	if f.Runs(SandboxName(siloB)) {
		t.Fatal("b runs with no Start of it (no claim): the gateway restored it and nothing stopped it")
	}
	if st, err := r.Status(ctx, siloB); err != nil || st.State != kri.Stopped {
		t.Fatalf("b: %v %v, want Stopped (so the agent claims it, then starts it)", st.State, err)
	}
}

// The Docker driver's container outlives a crashed gateway, so the silo reads Running (it is).
// An exec of it once brought the gateway back on the strength of the state file's Running flag,
// which outlives a kevasod restart and is no claim (review-batch4 claim 4): it now answers "not
// running" and starts nothing; only a claimed Start brings the gateway up.
func TestExecNeverBringsBackAGateway(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntimeOn(f, DriverDocker)
	started(t, r, silo)
	g := gatewayFor(DriverDocker, silo)
	f.Crash(g.Name())
	if st, err := r.Status(ctx, silo); err != nil || st.State != kri.Running {
		t.Fatalf("its container runs on: %v %v", st.State, err)
	}
	starts := f.ran("systemctl start " + g.Unit())
	if _, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"true"}}); err == nil {
		t.Fatal("exec with its gateway down succeeded")
	}
	if err := r.SetPolicy(ctx, silo, kri.Policy{Credentials: []kri.Credential{cred}}); err == nil {
		t.Fatal("a policy change with its gateway down succeeded")
	}
	if f.ran("systemctl start "+g.Unit()) != starts || f.units[g.Unit()] == "active" {
		t.Fatal("an exec or a policy change started the gateway")
	}
	if err := r.Start(ctx, silo); err != nil { // the claimed start
		t.Fatal(err)
	}
	if code, err := r.Exec(ctx, silo, kri.ExecRequest{Command: []string{"true"}}); err != nil || code != 0 {
		t.Fatalf("exec after its claimed start: %d %v", code, err)
	}
}
