package apiserver_test

import (
	"context"
	"errors"
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
	"kevaso.com/core/internal/moves"
	"kevaso.com/core/internal/store"
)

// K-013: a handoff whose source host died never ends by itself. The way out is a person's
// `kvo move --confirm-fenced` (the old copy is provably stopped): it must end the handoff, to the
// same destination or another one. Without the confirmation, or while the source is alive, the
// move is still refused.
func TestK013HandoffFromALostSourceEndsWithConfirmFenced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
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
	host := func(name string, lost bool) *v1.Host {
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
		return h
	}
	must(c.Create(ctx, &v1.Namespace{TypeMeta: tm("Namespace"), ObjectMeta: meta.ObjectMeta{Name: "d"}}))
	host("hv1", true) // drained, then died before its agent let go
	alive := host("hv0", false)
	host("hv2", false)
	host("hv3", false)
	handingOff := func(name, from string) {
		s := &v1.Silo{TypeMeta: tm("Silo"), ObjectMeta: meta.ObjectMeta{Name: name, Namespace: "d"},
			Spec: v1.SiloSpec{Runtime: "docker", Container: &v1.ContainerSource{Image: "app"}, Resources: v1.Resources{CPU: 1, Memory: "1Gi"}}}
		must(c.Create(ctx, s))
		s.Status.Host, s.Status.MovingFrom, s.Status.Phase = "hv2", from, "Scheduled"
		must(c.UpdateStatus(ctx, s))
	}
	move := func(name string, r moves.Request) (*v1.Silo, error) {
		var s v1.Silo
		err := c.Call(ctx, http.MethodPost, "/apis/kevaso/v1/namespaces/d/silos/"+name+"/move", r, &s)
		return &s, err
	}

	handingOff("a", "hv1")
	if _, err := move("a", moves.Request{To: "hv2"}); err == nil {
		t.Fatal("ended a handoff from a lost host without --confirm-fenced")
	}
	s, err := move("a", moves.Request{To: "hv2", ConfirmFenced: true})
	if err != nil {
		t.Fatalf("--confirm-fenced to the same destination: %v", err)
	}
	if s.Status.Host != "hv2" || s.Status.MovingFrom != "" || !moves.MayStart(s, "hv2") {
		t.Fatalf("handoff not ended: host %q, movingFrom %q", s.Status.Host, s.Status.MovingFrom)
	}

	handingOff("b", "hv1")
	if s, err = move("b", moves.Request{To: "hv3", ConfirmFenced: true}); err != nil {
		t.Fatalf("--confirm-fenced to another host: %v", err)
	}
	if s.Status.Host != "hv3" || s.Status.MovingFrom != "hv2" || moves.MayStart(s, "hv3") {
		t.Fatalf("to hv3: host %q, movingFrom %q (hv2, alive, lets go first)", s.Status.Host, s.Status.MovingFrom)
	}

	handingOff("c", alive.Name)
	var ce *client.Error
	if _, err := move("c", moves.Request{To: "hv2", ConfirmFenced: true}); !errors.As(err, &ce) || ce.Code != http.StatusConflict {
		t.Fatalf("ended a handoff whose source is alive: %v", err)
	}
}
