package mesh

import (
	"testing"

	"kevaso.com/core/builtin/kni"
)

// The silos' firewall lets silo addresses in only from the bridge and the mesh's devices: they
// must be these.
func TestFirewallKnowsTheMeshDevices(t *testing.T) {
	if len(kni.MeshDevices) != 2 || kni.MeshDevices[0] != Outer || kni.MeshDevices[1] != Inner {
		t.Fatalf("kni allows silo sources from %v; the mesh's devices are %s, %s", kni.MeshDevices, Outer, Inner)
	}
}
