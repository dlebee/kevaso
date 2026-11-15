package openshell

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

var cred = kri.Credential{Name: "api-key", Env: "API_KEY", Host: "api.example.com", Header: "Authorization", Bearer: true, Value: []byte("v1"), Version: 1}

// Item 4, K-080: Delete skipped the sandbox and reported success when the gateway didn't answer,
// and dropped Kevaso's state: the sandbox (and the credentials in the gateway's store) stayed
// with nothing left that knew of them. It returns the error and removes nothing it can't confirm.
func TestDeleteFailsWhenTheGatewayDoesNotAnswer(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	if err := r.SetPolicy(ctx, silo, kri.Policy{Credentials: []kri.Credential{cred}}); err != nil {
		t.Fatal(err)
	}
	g := gatewayFor(DriverVM, silo)
	f.hung[g.Name()] = true
	if err := r.Delete(ctx, silo); err == nil {
		t.Fatal("Delete with a silent gateway reported success")
	}
	if _, ok := r.load(silo); !ok || f.sandboxes[SandboxName(silo)] == nil || len(f.providers) != 1 {
		t.Fatalf("after a failed Delete: state kept %v, sandbox %v, providers %v", ok, f.sandboxes[SandboxName(silo)] != nil, f.providers)
	}
	f.hung[g.Name()] = false
	f.failOn = "provider delete"
	if err := r.Delete(ctx, silo); err == nil {
		t.Fatal("Delete whose provider delete failed reported success")
	}
	if _, ok := r.load(silo); !ok || len(f.providers) != 1 {
		t.Fatalf("after a failed provider delete: state kept %v, providers %v", ok, f.providers)
	}
	f.failOn = ""
	if err := r.Delete(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.load(silo); ok || len(f.sandboxes) != 0 || len(f.providers) != 0 {
		t.Fatalf("after Delete: state %v, sandboxes %v, providers %v", ok, f.sandboxes, f.providers)
	}
}

// Item 4: a stopped silo's gateway is down (item 1). Delete starts it to remove the sandbox (it
// skipped the sandbox before, so it stayed in the gateway's record), and with the last sandbox
// removes the gateway: its unit, user, home (registration and credential store) and port.
func TestDeleteRemovesTheSandboxAndWithTheLastOneTheGateway(t *testing.T) {
	ctx := context.Background()
	for _, d := range []string{DriverVM, DriverDocker} {
		f := newFake()
		r := newRuntimeOn(f, d)
		started(t, r, siloA, siloB)
		for _, id := range []kri.ID{siloA, siloB} {
			if err := r.Stop(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
		g := gatewayFor(d, siloA)
		if err := r.Delete(ctx, siloA); err != nil {
			t.Fatal(err)
		}
		if _, ok := f.sandboxes[SandboxName(siloA)]; ok {
			t.Fatalf("%s: the sandbox stayed in OpenShell", d)
		}
		if f.units[g.Unit()] == "active" || f.files[unitPath(g)] == nil || !f.users[g.User()] {
			t.Fatalf("%s: one of two deleted: the gateway must stay, down", d)
		}
		if err := r.Delete(ctx, siloB); err != nil {
			t.Fatal(err)
		}
		gws := map[string]Gateway{}
		_ = json.Unmarshal(f.files[gatewaysFile], &gws)
		home := false
		for p := range f.files {
			home = home || strings.HasPrefix(p, g.Dir()+"/")
		}
		if f.units[g.Unit()] == "active" || f.files[unitPath(g)] != nil || f.users[g.User()] || home || len(gws) != 0 || f.ran("systemctl daemon-reload") < 2 {
			t.Fatalf("%s: the last delete left the gateway: active %v, unit %v, user %v, home %v, registered %v", d,
				f.units[g.Unit()] == "active", f.files[unitPath(g)] != nil, f.users[g.User()], home, gws)
		}
	}
}

// Item 4, K-080: revoking a credential failed open: detach and delete errors were dropped and
// the provider forgotten, so a value Kevaso had revoked stayed in the gateway's store and
// attached. A revoke the gateway can't be told of is an error, and is retried.
func TestARevokeThatCannotBeToldIsNotDone(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	if err := r.SetPolicy(ctx, silo, kri.Policy{Credentials: []kri.Credential{cred}}); err != nil {
		t.Fatal(err)
	}
	name := ProfileID(silo, cred)
	f.failOn = "provider delete"
	if err := r.SetPolicy(ctx, silo, kri.Policy{}); err == nil {
		t.Fatal("a revoke whose provider delete failed reported success")
	}
	if s, _ := r.load(silo); s.Providers[name] == 0 || !f.providers[name] {
		t.Fatalf("after a failed revoke: Kevaso still knows it %v, the store has it %v", s.Providers[name] != 0, f.providers[name])
	}
	f.failOn = ""
	g := gatewayFor(DriverVM, silo)
	f.hung[g.Name()] = true
	if err := r.SetPolicy(ctx, silo, kri.Policy{}); err == nil {
		t.Fatal("a revoke with a silent gateway reported success")
	}
	f.hung[g.Name()] = false
	if err := r.SetPolicy(ctx, silo, kri.Policy{}); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.load(silo); len(s.Providers) != 0 || f.providers[name] {
		t.Fatalf("after the retry: providers %v, store %v", s.Providers, f.providers)
	}
}

// Item 4: a reset removes the sandbox of a stopped silo, whose gateway is down (item 1): it starts
// the gateway for this and takes it down again.
func TestAResetOfAStoppedSiloRemovesItsSandbox(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	if err := r.Stop(ctx, silo); err != nil {
		t.Fatal(err)
	}
	if err := r.Reset(ctx, kri.Spec{ID: silo, Image: "ubuntu-24.04"}); err != nil {
		t.Fatal(err)
	}
	g := gatewayFor(DriverVM, silo)
	if _, ok := f.sandboxes[SandboxName(silo)]; ok || f.units[g.Unit()] == "active" {
		t.Fatalf("after Reset: sandbox kept %v, gateway up %v", ok, f.units[g.Unit()] == "active")
	}
}
