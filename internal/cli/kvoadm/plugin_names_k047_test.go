package kvoadm

import (
	"testing"

	"kevaso.com/core/internal/operators"
)

// K-047 (plugin half): a plugin named x-node had the unit, kevaso-plugin-x-node.service, of
// plugin x's node side: installing one replaced the other. A name ending in -node is refused,
// by kvoadm plugin install and for an operator package alike.
func TestPluginNamesNeverTakeANodeSidesUnit(t *testing.T) {
	if _, err := parsePlugin([]string{"root@h", "--name", "linode-node", "--binary", "b"}, true); err == nil {
		t.Error("--name linode-node accepted")
	}
	if operators.ValidName("linode-node") {
		t.Error("an operator package named linode-node accepted")
	}
	if PluginUnitName("linode", "node") != "kevaso-plugin-linode-node.service" {
		t.Fatal("the node side's unit name changed: update this test")
	}
	for _, ok := range []string{"linode", "nodes", "node-a", "juicefs"} {
		if _, err := parsePlugin([]string{"root@h", "--name", ok, "--binary", "b"}, true); err != nil || !operators.ValidName(ok) {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
}
