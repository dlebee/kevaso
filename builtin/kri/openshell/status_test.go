package openshell

import (
	"context"
	"errors"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// Item 3, K-101: Status tells Running, Stopped and unknown apart. Whenever the gateway was silent
// the silo read Stopped, though a Docker-driver container may run on and though a hung gateway's
// VM runs on, and the agent then started it again (an everyBoot init ran again in a sandbox that
// never rebooted). A gateway that runs and doesn't answer is unknown (ErrGatewaySilent); its unit
// down, the look decides: the VM driver's sandbox can't run, the Docker driver's container is
// looked at.
func TestStatusTellsRunningStoppedAndUnknownApart(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		driver string
		crash  bool // the unit down (else: up and hung)
		want   kri.State
	}{
		{DriverVM, false, ""},
		{DriverDocker, false, ""},
		{DriverVM, true, kri.Stopped},
		{DriverDocker, true, kri.Running}, // its container runs on under dockerd
	} {
		f := newFake()
		r := newRuntimeOn(f, tc.driver)
		started(t, r, silo)
		g := gatewayFor(tc.driver, silo)
		if tc.crash {
			f.Crash(g.Name())
		} else {
			f.hung[g.Name()] = true
		}
		st, err := r.Status(ctx, silo)
		if tc.want == "" {
			if !errors.Is(err, ErrGatewaySilent) {
				t.Errorf("%s, hung gateway: %v %v, want ErrGatewaySilent (unknown)", tc.driver, st.State, err)
			}
			continue
		}
		if err != nil || st.State != tc.want {
			t.Errorf("%s, gateway down: %v %v, want %v", tc.driver, st.State, err, tc.want)
		}
	}
}

// Item 3, K-101: "not found" is decided by an exact answer, not a substring. A gateway the CLI
// doesn't know (its registration gone) says "gateway ... not found": that read as "the sandbox is
// gone" (Failed, and the fence counted it done). Only a list from the gateway without the sandbox
// says it's gone.
func TestNotFoundIsAnExactAnswer(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRuntime(f, "")
	started(t, r, silo)
	g := gatewayFor(DriverVM, silo)
	delete(f.registered, g.Name())
	if st, err := r.Status(ctx, silo); !errors.Is(err, ErrGatewaySilent) {
		t.Fatalf("its gateway unknown to the CLI: %v %q %v, want ErrGatewaySilent", st.State, st.Message, err)
	}
	f.registered[g.Name()] = true
	f.listFails = true
	delete(f.sandboxes, SandboxName(silo))
	if st, err := r.Status(ctx, silo); err == nil {
		t.Fatalf("get says not found and list doesn't answer: %v %q, want an error", st.State, st.Message)
	}
	f.listFails = false
	if st, err := r.Status(ctx, silo); err != nil || st.State != kri.Failed {
		t.Fatalf("the gateway lists no such sandbox: %v %v, want Failed (gone)", st.State, err)
	}
}
