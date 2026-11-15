package cloudhypervisor

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/sdk/kri"
)

// Found by the restart audit; fixed in the runtime (readState, created).

// kevasod killed during Create, after silo.json was saved and before the unit was written (in
// qemu-img convert, say: a restart's KillMode kills it): the next Create sees the state and
// returns at once, Status says Created, and Start fails on the missing unit (or boots a half-made
// disk) on every retry. The silo never comes up.
func TestACreateKilledHalfwayIsFinishedNextTime(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	ctx := context.Background()
	sp := spec("web")
	// What the killed Create left: its state, nothing else.
	b, _ := json.Marshal(State{ID: sp.ID, IP: "10.64.0.2", MAC: MAC(sp.ID), CPUs: 2, MemMiB: 4096})
	h.files[NamesFor(sp.ID).Dir+"/silo.json"] = b
	if err := r.Create(ctx, sp); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.files["/etc/systemd/system/"+NamesFor(sp.ID).Unit]; !ok {
		t.Fatalf("Create left the half-made silo as it was: %v", h.commands())
	}
}

// silo.json cut short (written in place before the atomic write; a disk error since): Status read
// it as no silo at all, the agent called Create, and Create removed the existing root LV and
// imaged a fresh one over it. A state file that's there but unreadable must be an error.
func TestAnUnreadableStateIsNotAnAbsentSilo(t *testing.T) {
	h := newFakeHost()
	r := newRuntime(t, h)
	sp := spec("web")
	h.files[NamesFor(sp.ID).Dir+"/silo.json"] = []byte(`{"id":{"namespace":"dev","na`)
	st, err := r.Status(context.Background(), sp.ID)
	if err == nil && st.State == kri.Absent {
		t.Fatal("an unreadable silo.json reads as an absent silo: Create would image a new root disk over the old")
	}
	if err := r.Create(context.Background(), sp); err == nil || strings.Contains(strings.Join(h.commands(), "\n"), "lvremove") {
		t.Fatalf("Create over an unreadable state: %v; %v", err, h.commands())
	}
}
