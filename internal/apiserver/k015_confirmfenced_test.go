package apiserver_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kevaso.com/core/api/client"
	"kevaso.com/core/api/meta"
	v1 "kevaso.com/core/api/v1"
	"kevaso.com/core/internal/apiserver"
	"kevaso.com/core/internal/clock"
	hostctl "kevaso.com/core/internal/controllers/host"
	siloctl "kevaso.com/core/internal/controllers/silo"
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// A confirm-fenced move must not be accepted while the silo's host has a fresh start claim on it
// (outside review of K-015's rule). moveSilo (moves.go) decides "the source host is lost"
// (fromLost, sourceLost) from hostctl.Lost(host), the Ready condition alone. A host whose Ready
// condition says Lost but which wrote a StartClaim on the silo moments ago (silo.StartClaimOf,
// silo.StartClaimFresh, counted by the control plane's own clock: controllers/host.Contacts) is
// in contact and about to run, or running, the silo: --confirm-fenced then moves it to a second
// host while the first starts it.
//
// How the handler knows the claim is fresh, without the leader's Contacts: the API server stamps
// a new or changed claim with its own clock when it receives it (moves.StampClaim), and the move
// handler judges its age by the same kind of clock (moves.CheckFenced: refused while younger than
// StartClaimFresh, unless the person insists). Fixed in fdbd9ce.
func TestK015ConfirmFencedIsRefusedWhileTheSourceHostHasAFreshStartClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	srv, err := apiserver.New(store.NewMemory(0), clock.NewFake(now))
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
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	for _, n := range []string{"hv1", "hv2"} {
		h := &v1.Host{TypeMeta: tm("Host"), ObjectMeta: meta.ObjectMeta{Name: n},
			Spec: v1.HostSpec{InternalIP: "10.0.0.1", Components: v1.HostComponents{Worker: &v1.WorkerSpec{Runtimes: []v1.RuntimeSpec{{Name: "docker"}}}}}}
		must(c.Create(ctx, h))
		h.Status.Runtimes = map[string]v1.RuntimeStatus{"docker": {State: "Ready"}}
		h.Status.Allocatable = v1.Resources{CPU: 4, Memory: "8Gi"}
		h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionTrue, LastTransitionTime: now}}
		if n == "hv1" { // its Ready condition says lost
			h.Status.Conditions = []meta.Condition{{Type: "Ready", Status: meta.ConditionUnknown, Reason: hostctl.ReasonLost, LastTransitionTime: now.Add(-time.Hour)}}
		}
		must(c.UpdateStatus(ctx, h))
	}
	s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: "s", Namespace: "d"},
		Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
	must(c.Create(ctx, s))
	s.Status.Host, s.Status.Phase = "hv1", "Scheduled"
	// hv1's agent claimed the start a moment ago: it is running, or about to run, the silo.
	s.Status.Conditions = []meta.Condition{{Type: siloctl.CondStartClaim, Status: meta.ConditionTrue, Reason: "Claimed",
		Message: "starting on hv1 at " + now.Format(time.RFC3339), LastTransitionTime: now}}
	must(c.UpdateStatus(ctx, s))

	var out v1.Silo
	err = c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/s/move", moves.Request{To: "hv2", ConfirmFenced: true}, &out)
	if err == nil {
		t.Fatalf("--confirm-fenced moved s to hv2 while hv1 has a fresh start claim on it: %+v", out.Status)
	}
}
