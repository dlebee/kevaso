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

// Deleting the host a silo is on confirms that copy is off, so a move does not ask for
// --confirm-fenced again. It does not confirm a lost status.movingFrom, and a fresh start
// claim of the deleted host still holds the silo.
func TestADeletedHostDoesNotConfirmALostSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
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
		t.Helper()
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
	host("hv1", true) // lost source of the handoff
	host("hv2", false)
	host("hv3", false)
	host("hv4", false)
	spec := v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"},
		Availability: v1.Availability{OnHostLoss: v1.OnHostLossRecreate}}
	put := func(name, on, from string) {
		t.Helper()
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"}, Spec: spec}
		must(c.Create(ctx, s))
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = on, from, "Scheduled"
		must(c.UpdateStatus(ctx, s))
	}
	move := func(name string, r moves.Request) (*v1.Silo, error) {
		t.Helper()
		var s v1.Silo
		err := c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/"+name+"/move", r, &s)
		return &s, err
	}
	put("plain", "hv2", "")
	put("hand", "hv2", "hv1")
	must(c.Delete(ctx, "Host", "", "hv2", client.Precondition{ConfirmOff: true}))

	plain, err := move("plain", moves.Request{To: "hv3", Recreate: true})
	if err != nil || plain.Status.Host != "hv3" || plain.Status.MovingFrom != "" {
		t.Fatalf("deleted current host, no handoff: %+v %v", plain.Status, err)
	}
	if _, err := move("hand", moves.Request{To: "hv3", Recreate: true}); err == nil || !strings.Contains(err.Error(), "hv1") {
		t.Fatalf("deleted current host confirmed the lost source: %v", err)
	}
	hand, err := move("hand", moves.Request{To: "hv3", Recreate: true, ConfirmFenced: true})
	if err != nil || hand.Status.Host != "hv3" || hand.Status.MovingFrom != "" {
		t.Fatalf("confirming the lost source: %+v %v", hand.Status, err)
	}

	put("claim", "hv4", "")
	var claim v1.Silo
	must(c.Get(ctx, "Silo", "d", "claim", &claim))
	claim.Status.Conditions = []meta.Condition{{Type: moves.CondStartClaim, Status: meta.ConditionTrue, Reason: "Starting",
		Message: "starting on hv4 at " + now.Format(time.RFC3339Nano), LastTransitionTime: now}}
	must(c.UpdateStatus(ctx, &claim))
	must(c.Delete(ctx, "Host", "", "hv4", client.Precondition{ConfirmOff: true}))
	_, err = move("claim", moves.Request{To: "hv3", Recreate: true})
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Code != http.StatusConflict || !strings.Contains(err.Error(), "claimed its start") {
		t.Fatalf("fresh claim of the deleted host: %v", err)
	}
}
