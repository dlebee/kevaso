package cloudhypervisor

import (
	"context"
	"fmt"

	"kevaso.com/core/sdk/kri"
)

// KillPlan is a kill: SIGKILL to everything in the VMM's unit (no power button, no waiting for the
// guest), then the same teardown a stop ends with (StopPlan: the VMM unit, then its virtiofsd
// daemons, in that order). What a stop keeps, a kill keeps too: the disk, its LVs and the TAP;
// those go with Delete.
func KillPlan(n Names, l Layout) [][]string {
	return append([][]string{{"systemctl", "kill", "--signal=SIGKILL", "--kill-whom=all", n.Unit}}, StopPlan(n, l)...)
}

// Kill implements kri.Killer: for a fence, the VM goes at once (a stop asks the guest to power off
// and waits up to 30s for it). Killing a stopped one only runs the teardown again (a no-op).
func (r *Runtime) Kill(ctx context.Context, id kri.ID) error {
	st, ok := r.state(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, kri.ErrNotFound)
	}
	for _, c := range KillPlan(NamesFor(id), st.layout()) {
		_, _ = r.Host.Run(ctx, c[0], c[1:]...) // each step is idempotent; one failing doesn't skip the rest
	}
	if r.active(ctx, NamesFor(id).Unit) == "active" {
		return fmt.Errorf("%s: the VMM is still running after SIGKILL", id)
	}
	return nil
}
