package kvoadm

import (
	"strings"
	"testing"
)

// K-067: an upgrade replaces the fence watcher too, before kevasod: an old watcher left running
// reads the new record its own way. Only where the host has one (a worker).
func TestAnUpgradeRestartsTheFenceWatcherFirst(t *testing.T) {
	fence, kevasod := strings.Index(upgradeRestart, "restart "+FenceUnitName), strings.Index(upgradeRestart, "restart kevasod")
	if fence < 0 || kevasod < 0 || fence > kevasod {
		t.Fatalf("the upgrade's restart: %q", upgradeRestart)
	}
	if !strings.Contains(upgradeRestart, "systemctl cat "+FenceUnitName) {
		t.Errorf("a host with no fence unit (no worker) must not fail the upgrade: %q", upgradeRestart)
	}
}
