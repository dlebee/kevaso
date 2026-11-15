package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/moves"
)

// The refusal of a confirm-fenced move while the host's start claim is fresh tells the person to
// add --insist: that flag must exist and do what it says, through the real kvo.
func TestKvoMoveInsistIsTheFlagTheRefusalNames(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := client.New(h.server)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(c.Create(ctx, ns("demo")))
	now := time.Now().UTC().Truncate(time.Second)
	for _, n := range []string{"hv1", "hv2"} {
		hst := &v1.Host{TypeMeta: meta.TypeMeta{APIVersion: v1.APIVersion, Kind: "Host"}, ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, hst))
		hst.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		hst.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		hst.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: now}}
		if n == "hv1" {
			hst.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost, LastTransitionTime: now.Add(-time.Hour)}}
		}
		must(c.UpdateStatus(ctx, hst))
	}
	s := containerSilo("web", "demo", "docker")
	s.Spec.Availability.OnHostLoss = v1.OnHostLossRecreate // a container moves only as a fresh copy (--recreate)
	must(c.Create(ctx, s))
	s.Status.Host, s.Status.Phase = "hv1", "Starting"
	s.Status.Conditions = []meta.Condition{{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting", Message: "starting on hv1 at " + now.Format(time.RFC3339Nano)}}
	must(c.UpdateStatus(ctx, s))

	_, errs, code := h.kvo(ctx, "", "move", "silo", "web", "-n", "demo", "--to", "hv2", "--recreate", "--confirm-fenced")
	if code == 0 || !strings.Contains(errs, "--insist") {
		t.Fatalf("a confirm-fenced move while hv1's claim is fresh: exit %d, %q; want refused, naming --insist", code, errs)
	}
	out, errs, code := h.kvo(ctx, "", "move", "silo", "web", "-n", "demo", "--to", "hv2", "--recreate", "--confirm-fenced", "--insist")
	if code != 0 {
		t.Fatalf("with --insist, as the refusal says: exit %d, %q", code, errs)
	}
	if !strings.Contains(out, "moving to hv2") {
		t.Fatalf("output: %q", out)
	}
}
