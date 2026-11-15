package apiserver_test

import (
	"strings"
	"testing"

	"kevaso.com/core/api/client"
	v1 "kevaso.com/core/api/v1"
)

// K-080 (until the owner decides): an OpenShell gateway brings its sandboxes back by itself (a
// restart of its unit, a reboot), outside Kevaso, so a silo there can't promise to stay stopped
// without the control plane: onControlPlaneLoss: Stop is refused on both OpenShell runtimes.
func TestStopOnControlPlaneLossIsRefusedOnOpenShell(t *testing.T) {
	c, ctx := setup(t)
	for _, rt := range []string{"openshell", "openshell-container"} {
		s := newSilo("os-" + strings.TrimPrefix(rt, "openshell"))
		s.Name = strings.TrimSuffix(s.Name, "-")
		s.Spec.Runtime, s.Spec.VM, s.Spec.Container = rt, nil, &v1.ContainerSource{Image: "ubuntu-24.04"}
		s.Spec.Availability = v1.Availability{OnControlPlaneLoss: v1.OnControlPlaneLossStop}
		if err := c.Create(ctx, s); !client.IsInvalid(err) || !strings.Contains(err.Error(), "brings its sandboxes back by itself") {
			t.Errorf("%s with onControlPlaneLoss: Stop: %v", rt, err)
		}
	}
}
