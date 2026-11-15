package container

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kevaso.com/core/builtin/kri/cloudhypervisor"
	"kevaso.com/core/sdk/kri"
)

// K-002 (network lane's half is in builtin/kni and internal/worker): the bridge binds each port
// to its silo's address and, where the runtime fixed one, its MAC. A VM's MAC is fixed (state
// "mac", cloudhypervisor.MAC); a container's veth peer gets a random one, so a container can still
// send frames with another silo's MAC (and pull that silo's frames to its own port as the bridge
// learns it). Fix (host lane): create the peer with `address cloudhypervisor.MAC(id)` and save it
// as "mac" in state.json; the worker then binds it with no change on its side.
func TestAContainersVethHasAFixedMACInItsState(t *testing.T) {
	t.Skip("K-002 host-lane half: the container runtime doesn't fix the veth peer's MAC yet (see the comment)")
	f := newFake()
	r := runtime(t, f)
	if err := r.Create(context.Background(), kri.Spec{ID: silo, Image: "ubuntu-24.04", CPU: 1, Memory: 256 << 20}); err != nil {
		t.Fatal(err)
	}
	n, mac := NamesFor(silo), cloudhypervisor.MAC(silo)
	want := "ip link add " + n.Veth + " type veth peer name " + n.Peer + " address " + mac
	found := false
	for _, c := range f.cmds {
		found = found || strings.HasPrefix(c, want)
	}
	if !found {
		t.Errorf("missing %q in:\n%s", want, strings.Join(f.cmds, "\n"))
	}
	var st struct {
		MAC string `json:"mac"`
	}
	if err := json.Unmarshal(f.files[n.Dir+"/state.json"], &st); err != nil || st.MAC != mac {
		t.Errorf("state.json mac %q (%v), want %q", st.MAC, err, mac)
	}
}
