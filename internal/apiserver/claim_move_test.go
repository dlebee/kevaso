package apiserver_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// Review of the start claim, item 1: hv1's clock is an hour behind, so by the stamps the control
// plane calls it lost, yet hv1 is alive and has just claimed its start of the silo (and is in
// Start). A person confirming "it is fenced" would start a second copy on hv2. The claim is
// evidence the host is alive: while one of the silo's own host stands (by when the API received
// it, never the agent's clock), a confirm-fenced move is refused and says when the host claimed;
// insist overrides it. Changes in internal/apiserver (surface lane): the minimal one, allowed.
func TestAConfirmFencedMoveIsRefusedWhileTheHostsFreshClaimStands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	clk := clock.NewFake(now)
	srv, err := apiserver.New(store.NewMemory(0), clk)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := client.New(ts.URL)
	tm := func(k string) meta.TypeMeta { return meta.TypeMeta{APIVersion: v1.APIVersion, Kind: k} }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	host := func(name string, lost bool) {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: name},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, h))
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: now}}
		if lost {
			h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost, LastTransitionTime: now.Add(-time.Hour)}}
		}
		must(c.UpdateStatus(ctx, h))
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	host("hv1", true)
	host("hv2", false)
	mk := func(name string) *v1.Silo {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
				Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}}
		must(c.Create(ctx, s))
		agentClock := now.Add(-time.Hour) // hv1's clock
		s.Status.Host, s.Status.Phase = "hv1", "Starting"
		s.Status.Conditions = []meta.Condition{{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting",
			Message: "starting on hv1 at " + agentClock.Format(time.RFC3339Nano), LastTransitionTime: agentClock}}
		must(c.UpdateStatus(ctx, s))
		return s
	}
	move := func(name string, r moves.Request) error {
		var out v1.Silo
		return c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/"+name+"/move", r, &out)
	}
	fenced := moves.Request{To: "hv2", Recreate: true, ConfirmFenced: true}

	mk("a")
	var got v1.Silo
	must(c.Get(ctx, "Silo", "d", "a", &got))
	if cl := meta.FindCondition(got.Status.Conditions, moves.CondStartClaim); cl == nil || !cl.LastTransitionTime.Equal(now) {
		t.Fatalf("the claim isn't stamped with when the API received it: %+v", cl)
	}
	clk.Step(10 * time.Second)
	err = move("a", fenced)
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusConflict || !strings.Contains(ce.Message, "claimed its start 10s ago") {
		t.Fatalf("a confirm-fenced move while hv1's claim is 10s old: %v", err)
	}
	// The same claim sent again (a status write that keeps it) doesn't make it younger.
	must(c.Get(ctx, "Silo", "d", "a", &got))
	got.Status.Phase = "Running"
	must(c.UpdateStatus(ctx, &got))
	clk.Step(21 * time.Second) // 31s since the claim
	if err := move("a", fenced); err != nil {
		t.Fatalf("31s after the claim: %v", err)
	}
	// Insisting overrides it at once.
	mk("b")
	insist := fenced
	insist.Insist = true
	if err := move("b", insist); err != nil {
		t.Fatalf("insisting: %v", err)
	}
}
