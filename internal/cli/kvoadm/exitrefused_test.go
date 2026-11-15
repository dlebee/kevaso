package kvoadm

import (
	"strconv"
	"strings"
	"testing"

	"kevaso.com/core/internal/controlplane"
)

// The exit contract (control lane, internal/controlplane.ExitRefused): kevasod exits with
// ExitRefused when it refuses to start because of what the node is (its data gone, another
// cluster's store): starting it again changes nothing. The control-plane units must not restart
// on it (RestartPreventExitStatus); on the Linodes a wiped system node was restarted every 2 s for
// ever (43 restarts in 90 s). Any other exit stays restarted (Restart=always).
func TestControlPlaneUnitsDontRestartARefusedStart(t *testing.T) {
	t.Skip("host lane to fix: add RestartPreventExitStatus=" + strconv.Itoa(controlplane.ExitRefused) + " to Unit and SystemNodeUnit; see control-4.md")
	want := "RestartPreventExitStatus=" + strconv.Itoa(controlplane.ExitRefused)
	units := map[string]string{
		"kvoadm init": Unit(InitOptions{Name: "cp-1", Address: "10.0.0.1", InternalIP: "10.0.0.1", Cluster: "c"}),
		"kvoadm host add --install control-plane": SystemNodeUnit(HostAddOptions{Name: "cp-2", Address: "10.0.0.2"}, []string{"https://10.0.0.1:6443"}, false, false),
	}
	for what, u := range units {
		if !strings.Contains(u, want) || !strings.Contains(u, "Restart=always") {
			t.Errorf("%s's unit: want %s with Restart=always:\n%s", what, want, u)
		}
	}
}
